from django.db import connections

def verificar_eligibilidad_prestamo(cedula, codptmo):
    # Use 'sqlserver' connection explicitly from Django's connections object
    with connections['sqlserver'].cursor() as cursor:
        cursor.execute("SELECT REFINANCIA, MINCUOPAGO, FRECUENCIA, DESCRIP, RECPRE FROM PRESTAMO WHERE CODPTMO = %s", [codptmo])
        datos_prestamo = cursor.fetchone()

        if not datos_prestamo:
            return {'error': 'Préstamo no encontrado.'}

        refi, min_cuota, frecuencia, descrip, recaudos_ptmo = datos_prestamo

        # Verificar si el socio está habilitado para realizar este préstamo
        cursor.execute("SELECT STATUS FROM SOCIOS WHERE CEDSOC = %s", [cedula])
        estado_socio = cursor.fetchone()

        if estado_socio and estado_socio[0] not in ['A', 'J', 'P']:
            return {'error': 'El socio no puede realizar este préstamo. No está habilitado para realizar operaciones.'}

        # Verificar si el socio tiene demostraciones pendientes
        cursor.execute("SELECT dbo.fn_DemostracionesPendientes(%s)", [cedula])
        demostraciones_pendientes = cursor.fetchone()[0]

        if demostraciones_pendientes != 0 and codptmo != 1:
            return {'error': 'El socio no puede realizar este préstamo. Tiene demostraciones pendientes.'}

        # Verificar si el socio ha superado la frecuencia de préstamos otorgados
        cursor.execute("SELECT dbo.fn_DemostracionesPendientes(%s)", [cedula])
        prestamos_otorgados = cursor.fetchone()[0]

        if frecuencia != 0 and prestamos_otorgados >= frecuencia:
            return {'error': 'El socio no puede realizar este préstamo. Excede el número de préstamos otorgados por este concepto.'}

        # Verificar si el socio ya tiene una solicitud de préstamo pendiente para este préstamo
        cursor.execute("SELECT dbo.fn_SolicitudPtmoPendiente(%s, %s)", [cedula, codptmo])
        solicitud_existente = cursor.fetchone()[0]

        if solicitud_existente != 0:
            return {'error': 'El socio no puede realizar este préstamo. Ya tiene una solicitud pendiente para este préstamo.'}

        # Verificar si el socio cumple con el tiempo mínimo requerido para este préstamo
        cursor.execute("SELECT dbo.fn_AntiguedadMinima(%s, %s)", [codptmo, cedula])
        antiguedad_minima = cursor.fetchone()[0]

        if antiguedad_minima != 0:
            return {'error': 'El socio no puede realizar este préstamo. No cumple con el tiempo mínimo requerido.'}

        # Verificar si el socio tiene un saldo pendiente en un préstamo activo
        cursor.execute("SELECT dbo.fn_ExisteSaldo(%s, %s)", [cedula, codptmo])
        saldo_existente = cursor.fetchone()[0]

        if refi == 'N' and saldo_existente != 0:
            return {'error': f'El socio no puede realizar este préstamo. Posee un saldo pendiente de {saldo_existente}. Verifique los detalles del préstamo.'}

        # Si el préstamo es no refinanciado y el saldo es 0, verificar las cuotas pagadas
        if saldo_existente == 0 and refi == 'N':
            cursor.execute("SELECT dbo.fn_NCPM(%s)", [cedula])
            cuotas_pagadas = cursor.fetchone()[0]

            if cuotas_pagadas < min_cuota:
                return {'error': f'El socio no puede realizar este préstamo. No cumple con el pago mínimo de {min_cuota} cuotas. (Pagado: {cuotas_pagadas}).'}

            # Verificar si ha cumplido con las cuotas mínimas canceladas
            cursor.execute("SELECT dbo.fn_MinimoCuotasCanceladas(%s, %s)", [cedula, codptmo])
            cuotas_canceladas = cursor.fetchone()[0]

            if cuotas_canceladas != 0:
                return {'error': 'El socio no puede realizar este préstamo. Aún no se cumple el plazo mínimo requerido desde el último préstamo.'}

        # Si todo está bien, permitir que el socio solicite el préstamo
        return {'message': 'El socio puede solicitar este préstamo.'}
