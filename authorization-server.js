const fs = require("fs")
const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
const {
	randomString,
	containsAll,
	decodeAuthCredentials,
	timeout,
} = require("./utils")

const config = {
	port: 9001,
	privateKey: fs.readFileSync("assets/private_key.pem"),

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
}

const clients = {
	"my-client": {
		name: "Sample Client",
		clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
		scopes: ["permission:name", "permission:date_of_birth"],
	},
	"test-client": {
		name: "Test Client",
		clientSecret: "TestSecret",
		scopes: ["permission:name"],
	},
}

const users = {
	user1: "password1",
	john: "appleseed",
}

const requests = {}
const authorizationCodes = {}

let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/authorization-server")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/*
Your code here
*/
app.get("/authorize", (res, req) => {
	const id = req.query.client_id;
	const client = clients[id];
	if(!client) return res.status(401).end();

	const scope = req.query.scope.split(" ");

	const containsScopes = containsAll(client.scopes, scope);
	const requestId = randomString();

	res.render("login", { client, scope, requestId })

	return res.end(200)
});

app.post("/approve", (res, req) => {
	const { userName, password, requestId } = req.body;
	const clientReq = requests[requestId];
	if(users[userName] !== password || !clientReq) return res.status(401);
	delete requests[requestId];
	const requestID = randomString();
	authorizationCodes[requestID] = { clientReq, userName };
	const { redirect_uri, state } = clientReq;
	redirect_uri.searchParams.append('code', requestID);
	redirect_uri.searchParams.append('state', state);
	res.redirect(redirect_uri)

})

app.post('/token', (res, req) => {
	const authorization = req.headers.authorization;
	if(!authorization) res.status(401);

	const { clientId, clientSecret } = decodeAuthCredentials(authorization)

	const client = clients[clientId];
	if(client.secret !== clientSecret) return res.status(401);

	const {code} = req.body;
	const authCode = authorizationCodes[code];
	if(!authCode) return res.status(401);
	delete authorizationCodes[code];

	const token = jwt.sign(authCode.userName, authCode.clientReq.scope)

	return res.status(200).json({access_token: token, token_type: "Bearer" })
})

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes

module.exports = { app, requests, authorizationCodes, server }
