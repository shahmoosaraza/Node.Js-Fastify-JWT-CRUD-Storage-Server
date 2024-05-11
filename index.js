const fs = require('fs').promises;
const fastify = require('fastify')({logger:true});
const jwt = require('jsonwebtoken');
const {createHash} = require('crypto');

// Chiave segreta per JSON Web Token
const JWT_SECRET_KEY = 'my_secret_key';

// Percorso del file JSON per lo storage dei dati
const DATA_FILE_PATH = './data.json';

// Percorso del file JSON per lo storage dei dati dell'utente.
// Per lo svolgimento di questo esercizio è opzionale.
const USER_DATA_FILE_PATH = './user.json'

let users = [];

const userData = async() => {
    try {
        const userFileData = await fs.readFile(USER_DATA_FILE_PATH, 'utf-8');
        const parseData = JSON.parse(userFileData);
        users = Object.values(parseData);  
    } catch(error){
        console.error('ERROR in Loading Users Data: ', error);
        users = [];
    }
};
userData();

// Definizione dello schema JSON utilizzato per la validizione del body della richiesta POST/register e POST/login
const userSchema = {
    body: {
        type: 'object',
        required: ['email', 'password'],
        properties: {
            email: {type: 'string', format: 'email'},
            password: {type: 'string', minLength: 8},
        },
    },
};

// Definizione dello schema JSON utilizzato per la validizione del body della richiesta PATCH/update-user
const updateUserSchema = {
    body: {
        type: 'object',
        minProperties: 1,
        anyOf: [
            {required: ['email']},
            {required: ['password']},
            {required: ['role']}
        ],
        properties: {
            email: {type: 'string', format: 'email'},
            password: {type: 'string', minLength: 8},
            role: {type: 'string', enum:['user', 'superuser']}
        },
    },
};

// Definizione dello schema JSON utilizzato per la validizione del body della richiesta POST/data
// Lo schema per la validazione del body richiede due parametri key e data.
const postSDataSchema = {
    body: {
        type: 'object',
        required: ['key', 'data'],
        properties: {
            key: {type: 'string'},
            data: {type: 'string'},
        },
    },
};

// Definizione dello schema JSON utilizzato per la validizione del body della richiesta PATCH/data
const patchDataSchema = {
    body: {
        type: 'object',
        required: ['data'],
        properties: {
            data: {type: 'string'},
        },
    },
};

// La funzione asincrona 'authenticateJWT' è una funzione che verifica il token JWT. 
// La funzione garantisce che gli endpoint che richiedono l'autenticazione, prima verificano la valdiità del token JWT.
// Se il token JWT è valido, la richiesta può procedere; altrimenti, l'accesso viene negato e viene inviata un errore 403.
const authenticateJWT = async (request, reply) => {
    try {
        // Viene estratto il token JWT dall'header Authorization della richiesta HTTP
        const token = request.headers['authorization'].replace('Bearer ', '');
        // Viene verificato il token JWT usando la chiave segreta JWT_SECRET_KEY. Se il token è valido, restituisce il payload del token JWT decodificato; altrimenti genera un errore.
        const payload = jwt.verify(token, JWT_SECRET_KEY);
        request.user = payload;
    } catch(error){
        reply.code(403).send({error: 'ERROR 403: Forbidden'});
    }
};

// ENDPOINT USER
// 1. POST/register - Registra un nuovo utente.
fastify.post('/register', {schema :userSchema}, async (request, reply) => {
    const {email, password} = request.body;
    // Controlla se esiste gia' un l'utente con la stessa mail.
    const registeredUser = users.find(user => user.email === email);
    if(registeredUser){
        reply.code(400).send({error: 'ERROR 400 - User with this email already registered'});
        return;
    }
    // La password viene hashata con l'algoritmo SHAH256.
    const hashpassword = createHash('sha256').update(password).digest('hex');
    const newUser = {id: users.length + 1, email, password: hashpassword, role: 'user' };
    users.push(newUser);
    // Aggiornamento del file user.json con i dati del nuovo utente
    try{
        const userFileData = JSON.parse(await fs.readFile(USER_DATA_FILE_PATH, 'utf-8'));
        const newUserData = { ...userFileData, [newUser.id]: newUser};
        // Il metodo JSON.stringify serve per convertire i dati in formato JSON,
        // Il secondo parametro (in questo caso null) rappresenta la funzione replacer, che consente di controllare come o quali valori devono essere nel JSON risultante.
        // Il '2' è lo spazio di indentazione del JSON risultante.
        await fs.writeFile(USER_DATA_FILE_PATH, JSON.stringify(newUserData, null, 2));
    } catch (error){
        console.error('ERROR in Saving User Data: ', error);
    }    
    reply.code(201).send({message: 'User registered successfully'});
});

// ENDPOINT USER
// 2. POST/login - Effettua login e riceve in risposta il JWT.
fastify.post('/login', {schema :userSchema}, async (request, reply) => {
    const {email, password} = request.body;
    // Autenticazione dell'utente tramite l'email e la password hashata,
    const user = users.find(u => u.email === email);
    if(!(user && user.password ===  createHash('sha256').update(password).digest('hex'))){
        reply.code(401).send({error: 'ERROR 401: Unauthorized'});
        return;
    }
    // Generazione del token JWT per l'utente loggato.
    const token = jwt.sign({id:user.id, email: user.email, role: user.role}, JWT_SECRET_KEY);
    reply.send({token});
});

// ENDPOINT USER
// 3. *DELETE/delete - Elimina l'utente attualmente loggato.
// In Fastify, preHandler è un'opzione che consente di definire una funzione da eseguire prima di gestire la richiesta principale.
// In questo caso authenticaJWT è la funzione che verifica il token JWT
fastify.delete('/delete',{preHandler:authenticateJWT}, async (request, reply) =>{
    const userId = request.user.id;
    // Il metodo filter ritorna un nuovo array degli user, togliendo il user attuale (da eliminare).
    users = users.filter(u => u.id !== userId);
    // Aggiornamento del file user.json, cancellando l'utente attualmente loggato.
    try{
        const userFileData = JSON.parse(await fs.readFile(USER_DATA_FILE_PATH, 'utf-8'));
        delete userFileData[userId];
        await fs.writeFile(USER_DATA_FILE_PATH, JSON.stringify(userFileData, null, 2));
    } catch (error){
        console.error('ERROR in Deleting/Updating User Data: ', error);
    }    
    reply.send({message: 'User deleted successfully'});
});

// ENDPOINT USER
// 4. PATCH/update-user/:id - Aggiorna i dati di un utente.
// Questo endpoint è accessibile solo al superuser.
// Tramite questo endpoint il superuser può modificare i dati (email e password) e modificare il ruolo (da user a superuser)

fastify.patch('/update-user/:email', {schema :updateUserSchema, preHandler: authenticateJWT}, async (request, reply) =>{
    const {email} = request.params;
    const {email: newEmail, password: newPassword, role: newRole} = request.body;
    if(request.user.role !== 'superuser'){
        reply.code(403).send({error: 'ERROR 403: Forbidden, Only superusers can perform this operation.'})
        return;
    }
    const userToUpdate = email ? users.find(u => u.email === email):null;
    if(!userToUpdate){
        reply.code(404).send({error : 'ERROR 404: User not Found'});
        return;
    }
    // Aggiorna i dati dell'utente
    // Viene controllato se sono stati forniti nuovi valori per l'email, la password e il ruolo dell'utente.
    // Lo schmema richiede almeno un parametro da aggiornare, nel caso vengono omessi uno o due parametri, quelli non vengono aggiornati.
    // I dati dell'utente vengono aggiornati con i nuovi valori.
    if (newEmail) userToUpdate.email = newEmail;
    if (newPassword) userToUpdate.password = createHash('sha256').update(newPassword).digest('hex');
    if (newRole) userToUpdate.role = newRole;
    // Aggiornamento del file user.json con i dati aggiornati.
    try{
        const userFileData = JSON.parse(await fs.readFile(USER_DATA_FILE_PATH, 'utf-8'));
        userFileData[userToUpdate.id] = userToUpdate;
        await fs.writeFile(USER_DATA_FILE_PATH, JSON.stringify(userFileData, null, 2));
    } catch(error) {
        console.error('ERROR - Not able to update user data: ', error);
        reply.code(500).send({error: 'ERROR 500'});
        return;
    }
})

// ENDPOINT DATA
// 1. *POST/data - Carica dei dati nuovi
fastify.post('/data', {schema :postSDataSchema, preHandler: authenticateJWT}, async (request, reply) => {
    const {key, data} = request.body;
    // Lettura del contenuto del file JSON
    const fileData = await fs.readFile(DATA_FILE_PATH, 'utf-8').catch(() => '{}');
    // Parsing del contenuto JSON
    const parseData = JSON.parse(fileData);
    // Aggiungiamo i nuovi dati all'oggetto dei dati parsificati.
    parseData[key] = data;
    // Scrittura dei dati aggiornati nel file data.JSON.
    await fs.writeFile(DATA_FILE_PATH, JSON.stringify(parseData, null, 2));
    reply.code(201).send({message: 'Data saved successfully'});
});

// ENDPOINT DATA
// 2. *GET/data/:key - Ritorna i dati corrispondenti alla chiave
fastify.get('/data/:key', {preHandler: authenticateJWT}, async (request, reply) => {
    // Viene estratto il valore del parametro key dalla richiesta GET (la chiave di cui ci servono i dati)
    const key = request.params.key
    const fileData = await fs.readFile(DATA_FILE_PATH, 'utf8').catch(() => '{}');
    const parseData = JSON.parse(fileData);
    // Vengono recuperati i dati corrispondenti alla chiave key.
    const data = parseData[key];
    if(!data){
        reply.code(404).send({error: 'Data not found'});
        return;
    }
    reply.send({data});
});

// ENDPOINT DATA
// 3. *PATCH/data/:key - Aggiorna i dati corrispondenti alla chiave
fastify.patch('/data/:key', {schema :patchDataSchema, preHandler: authenticateJWT}, async(request, reply) => {
    const key = request.params.key;
    const newData = request.body.data;
    const fileData = await fs.readFile(DATA_FILE_PATH, 'utf8').catch(() => '{}');
    const parseData = JSON.parse(fileData);
    parseData[key] = newData;
    await fs.writeFile(DATA_FILE_PATH, JSON.stringify(parseData, null, 2));
    reply.send({message: 'Data updated succesfully'});
});

// ENDPOINT DATA
// 4. *DELETE/data/:key - Elimina i dati corrispondenti alla chiave
fastify.delete('/data/:key', {preHandler: authenticateJWT}, async (request, reply) => {
    const key = request.params.key;
    const fileData = await fs.readFile(DATA_FILE_PATH, 'utf8').catch(() => '{}');
    const parseData = JSON.parse(fileData);
    delete parseData[key];
    await fs.writeFile(DATA_FILE_PATH, JSON.stringify(parseData, null, 2));
    reply.send({message: 'Data deleted successfully'});
});

// Avvio del server
const start = async () => {
    try {
        // Avvio del server Fastify in ascolto per richieste sulla porta 3000.
        // await viene utilizzato perchè listen è un metodo asincrono che ritorna una 'promessa' 
        await fastify.listen(3000)
        fastify.log.info('Server listening on port 3000');
    }   catch(err){
        fastify.log.error(err);
        process.exit(1);
    }
};

start();