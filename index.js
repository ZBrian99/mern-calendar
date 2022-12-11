const express = require('express');
const cors = require('cors')
const { dbConnection } = require('./database/config');
require('dotenv').config()




// Crear el servidor de express
const app = express();

// Base de datos

dbConnection();
app.use(cors());
// Directorio Publico
app.use(express.static('public'))


// Lectura y parseo del body

app.use(express.json())


//Rutas
app.use('/api/auth', require('./routes/auth'))
app.use('/api/events', require('./routes/events'))
// TODO: CRUD: Eventos

app.get('*', (req, res) => {
  res.sendFile(__dirname + '/public/index.html')
})


//Escuchar
app.listen(process.env.PORT, () => {
	console.log(`Servidor conrriendo en puerto ${process.env.PORT}`);
});