// Rutas de Usuarios / Events
// host + /api/events

// Todas tienen que pasar por la validacion
const { Router } = require('express');

const { check } = require('express-validator');

const { validarCampos } = require('../middlewares/validar-campos');

const { getEventos, actualizarEvento, eliminarEvento, crearEvento } = require('../controllers/events');
const { validarJWT } = require('../middlewares/validar-jwt.');
const { isDate } = require('../helpers/isDate');

const router = Router();

// Cada evento pasa por la validacion
router.use(validarJWT);

// Obtener eventos
router.get('/', getEventos);

// Crear un nuevo evento
router.post(
	'/',
	[
		check('title', 'El titulo es obligatorio').not().isEmpty(),
		check('start', 'Fecha de inicio es obligatorio').custom(isDate),
		check('end', 'Fecha de finalizacion es obligatorio').custom(isDate),
		validarCampos,
	],
	crearEvento
);

// Actualizar evento
router.put('/:id', actualizarEvento);

// Eliminar evento
router.delete('/:id', eliminarEvento);
module.exports = router;
