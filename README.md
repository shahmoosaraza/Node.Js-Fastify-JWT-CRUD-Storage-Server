<h1 align="center">NodeJS Fastify JWT CRUD Storage Server</h1>

<p align="center">
  <em>This is a Node.js server application built with Fastify that implements CRUD (Create, Read, Update, Delete) operations along with JWT (JSON Web Token) authentication for data storage.</em>
</p>

## Features

- User registration and login with password hashing using SHA256.
- JWT-based authentication for secure API endpoints.
- CRUD operations for data storage using JSON files.
- Role-based access control with a superuser role.
- Error handling for unauthorized access and data not found scenarios.

## Technologies Used

- Node.js
- Fastify
- JSON Web Tokens (JWT)

## Installation

1. Clone the repository:
   
```
git clone https://github.com/shahmoosaraza/nodejs-fastify-jwt-crud-storage-server.git
```
3. Install dependencies:
```
cd nodejs-fastify-jwt-crud-storage-server
npm install
```

3. Start the server:
```
npm start
```

## Endpoints

- **POST /register**: Register a new user. (Schema validation: userSchema)
- **POST /login**: Login and receive a JWT. (Schema validation: userSchema)
- ***DELETE /delete**: Delete the currently logged-in user. (Schema validation: None, Protected)
- ***PATCH /update-user/:email**: Update user data. (Schema validation: updateUserSchema, Protected)
- ***POST /data**: Create new data. (Schema validation: postSDataSchema, Protected)
- ***GET /data/:key**: Retrieve data by key. (Schema validation: None, Protected)
- ***PATCH /data/:key**: Update data by key. (Schema validation: patchDataSchema, Protected)
- ***DELETE /data/:key**: Delete data by key. (Schema validation: None, Protected)

*Note: Endpoints marked with "***" are protected and require JWT authentication. Schema validation is performed for request bodies as mentioned above.*

## Usage

You can test the server using tools like Postman or curl. Make sure to include the JWT token in the Authorization header for protected endpoints.



