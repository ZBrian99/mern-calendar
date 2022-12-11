const { response } = require('express');
const bcrypt = require('bcryptjs');
const User = require('../models/User');

const { generarJWT } = require('../helpers/jwt');

const crearUsuario = async (req, res = response) => {
	const { name, email, password } = req.body;

	try {
		let user = await User.findOne({ email });

		if (user) {
			return res.status(400).json({
				ok: false,
				msg: 'Un usuario ya existe con ese email',
			});
		}

		user = new User(req.body);

		// Encriptar contraseña

		const salt = bcrypt.genSaltSync();
		user.password = bcrypt.hashSync(password, salt);

		await user.save();

		// Generar nuestro JWT

		const token = await generarJWT(user.id, user.name);

		res.status(201).json({
			ok: true,
			uid: user.id,
			name: user.name,
			token,
		});
	} catch (error) {
		console.log(error);
		res.status(500).json({
			ok: false,
			msg: 'Error en la carga',
		});
	}
};

const loginUsuario = async (req, res = response) => {
	const { email, password } = req.body;

	try {
		const user = await User.findOne({ email });

		if (!user) {
			return res.status(400).json({
				ok: false,
				msg: 'Un usuario no existe con ese email',
			});
		}

		// Confirmar contraseñas

		const validPassword = bcrypt.compareSync(password, user.password);

		if (!validPassword) {
			return res.status(400).json({
				ok: false,
				msg: 'Contraseña incorrecta',
			});
		}

		// Generar nuestro JWT

		const token = await generarJWT(user.id, user.name);

		res.json({
			ok: true,
			uid: user.id,
			name: user.name,
			token,
		});
	} catch (error) {
		console.log(error);
		res.status(500).json({
			ok: false,
			msg: 'Error en la carga',
		});
	}
};
const revalidarToken = async(req, res = response) => {

  const {uid, name}= req

  //generar un nuevo JWT y retornarlo en esta peticion

  const token = await generarJWT(uid, name)


	res.json({
		ok: true,
		token,
	});
};

module.exports = { crearUsuario, loginUsuario, revalidarToken };
