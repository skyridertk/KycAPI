// eslint-disable-next-line strict
let express = require('express');
let cors = require('cors');
const uuid = require('uuid');
const fabricUser = require('./registerUserAPI');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const { MongoClient } = require('mongodb');
const { Wallets, FileSystemWallet, Gateway } = require('fabric-network');
const path = require('path');
const fs = require('fs');
const multer = require('multer');

let app = express();

const upload = multer({ dest: 'uploads/' });

dotenv.config();

app.use(cors({
    origin: '*'
}));

app.use(express.json());
app.use(express.urlencoded({ extended: false })); // for parsing application/x-www-form-urlencoded


const uri = 'mongodb://root:1234@localhost:27017/?authSource=admin&readPreference=primary&appname=MongoDB%20Compass&ssl=false';

const client = new MongoClient(uri);
const dbName = 'test';

client.connect().then(r => {
    console.log('Connected successfully to server');
});

function generateToken(user) {
    const token = jwt.sign({
        data: user.uuid,
    }, process.env.TOKEN_SECRET, {
        expiresIn: '1h'
    });
    return token;
}

function handleLogin(user, password, res) {
    try {

        if (user.length > 0) {
            user = user[0];
            if (bcrypt.compareSync(password, user.password)) {
                const token = generateToken(user);

                return res.status(200).json({
                    message: 'User logged in successfully',
                    token: token
                });
            } else {
                return res.status(400).json({
                    message: 'Incorrect password',
                    token: false
                });
            }
        } else {
            return res.status(400).json({
                message: 'User does not exist',
                token: false
            });
        }
    } catch (error) {
        return res.status(500).json({
            message: `Something went wrong: ${error}`,
            token: false
        });
    }
}

async function handleGateway(ccp, wallet, uuid, channel, my_contract) {
    // Create a new gateway for connecting to our peer node.
    const gateway = new Gateway();
    await gateway.connect(ccp, {wallet, identity: uuid, discovery: {enabled: true, asLocalhost: true}});

    // Get the network (channel) our contract is deployed to.
    const network = await gateway.getNetwork(channel);

    // Get the contract from the network.
    const contract = network.getContract(my_contract);
    return {gateway, contract};
}

async function loadWallet(uuid) {
    // load the network configuration
    const ccpPath = path.resolve(__dirname, '..', 'config', 'connection-profile', 'org1-network.json');
    let ccp = JSON.parse(fs.readFileSync(ccpPath, 'utf8'));

    // Create a new file system based wallet for managing identities.
    const walletPath = path.join(process.cwd(), 'wallet');
    const wallet = await Wallets.newFileSystemWallet(walletPath);
    console.log(`Wallet path: ${walletPath}`);

    // Check to see if we've already enrolled the user.
    const identity = await wallet.get(uuid);
    return {ccp, wallet, identity};
}

async function invoke(uuid, res, my_contract, channel) {
    try {
        let {ccp, wallet, identity} = await loadWallet(uuid);
        if (!identity) {
            return res.status(500).json({
                message: 'An identity for the user "${uuid}" does not exist in the wallet'
            });
        }

        const {gateway, contract} = await handleGateway(ccp, wallet, uuid, channel, my_contract);

        await contract.submitTransaction('createAccount', '', '', '', '');
        console.log('Transaction has been submitted');

        await gateway.disconnect();

        return res.status(200).json({
            message: 'Transaction has been submitted'
        });

    } catch (error) {

        return res.status(500).json({
            message: `Failed to submit transaction: ${error}`
        });
    }
}

async function getKyc(type, res, my_contract, channel) {
    try {
        let {ccp, wallet, identity} = await loadWallet(uuid);
        if (!identity) {
            return res.status(500).json({
                message: 'An identity for the user "${uuid}" does not exist in the wallet'
            });
        }

        const {gateway, contract} = await handleGateway(ccp, wallet, uuid, channel, my_contract);

        // Evaluate the specified transaction.
        const result = await contract.evaluateTransaction(type);
        console.log(`Transaction has been evaluated, result is: ${result.toString()}`);


        await gateway.disconnect();
        return res.status(200).json({response: result.toString()});

    } catch (error) {
        //console.error(`Failed to evaluate transaction: ${error}`);
        res.status(500).json({error: error});
    }
}

async function getCustomer(type, res, my_contract, channel) {
    try {
        let {ccp, wallet, identity} = await loadWallet(uuid);
        if (!identity) {
            return res.status(500).json({
                message: 'An identity for the user "${uuid}" does not exist in the wallet'
            });
        }

        const {gateway, contract} = await handleGateway(ccp, wallet, uuid, channel, my_contract);

        // Evaluate the specified transaction.
        const result = await contract.evaluateTransaction(type);
        console.log(`Transaction has been evaluated, result is: ${result.toString()}`);


        await gateway.disconnect();
        return res.status(200).json({response: result.toString()});

    } catch (error) {
        //console.error(`Failed to evaluate transaction: ${error}`);
        res.status(500).json({error: error});
    }
}

async function saveKyc(res, my_contract, channel, userData) {
    try {
        let {ccp, wallet, identity} = await loadWallet(uuid);
        if (!identity) {
            return res.status(500).json({
                message: 'An identity for the user "${uuid}" does not exist in the wallet'
            });
        }

        const {gateway, contract} = await handleGateway(ccp, wallet, uuid, channel, my_contract);

        //submit transaction
        await contract.submitTransaction('createKYC', 'asset13', userData.firstname, userData.lastname, userData.address, userData.dateOfBirth, userData.gender, userData.status, userData.approvalCount, userData.owner, userData.proofOfResidence, userData.proofOfId);


        await gateway.disconnect();
        return res.status(200).json({message: 'Success'});

    } catch (error) {
        //console.error(`Failed to evaluate transaction: ${error}`);
        res.status(500).json({error: error});
    }
}

async function saveCustomer(res, my_contract, channel, userData) {
    try {
        let {ccp, wallet, identity} = await loadWallet(uuid);
        if (!identity) {
            return res.status(500).json({
                message: 'An identity for the user "${uuid}" does not exist in the wallet'
            });
        }

        const {gateway, contract} = await handleGateway(ccp, wallet, uuid, channel, my_contract);

        //submit transaction
        await contract.submitTransaction('createCustomer', 'asset13', userData.email, userData.uuid);

        await gateway.disconnect();
        return res.status(200).json({message: 'Success'});

    } catch (error) {
        //console.error(`Failed to evaluate transaction: ${error}`);
        return res.status(500).json({error: error});
    }
}

app.post('/api/register', async (req, res) => {
    try {

        let user = await client.db(dbName).collection('users').find({email: req.body.email}).toArray();

        if (user.length > 0) {
            return res.status(400).json({
                message: `User with email ${req.body.email} already exists`
            });
        } else {

            const UUID = uuid.v4();
            let fabRes = await fabricUser.Enroll(UUID);

            const {password} = req.body;
            const salt = bcrypt.genSaltSync(10);
            req.body.password = bcrypt.hashSync(password, salt);
            req.body.uuid = UUID;
            req.body.email = req.body.email.toLowerCase();

            let user = await client.db(dbName).collection('users').insertOne(req.body);

            const token = jwt.sign({
                data: user.uuid,
            }, process.env.TOKEN_SECRET, {
                expiresIn: '1h'
            });

            // await saveCustomer(res, my_contract, channel, req.body);

            return res.status(200).json({
                message: 'User created successfully',
                token: token
            });
        }
    } catch (error) {

        return res.status(500).json({
            message: `Something went wrong: ${error}`
        });

    }

});

app.post('/api/login', async (req, res) => {
    const { email, password} = req.body;

    let user = await client.db(dbName).collection('users').find({email}).toArray();

    return handleLogin(user, password, res);
});

app.post('/api/admin_login', async (req, res) => {
    const { email, password} = req.body;

    let user = await client.db(dbName).collection('admin').find({email}).toArray();

    return handleLogin(user, password, res);
});

app.get('/api/admin_validate', async (req, res)=>{

    //token from header
    const token = req.headers.token;

    //throw error if token is not present
    if(!token){
        return res.status(401).json({
            message: 'No token provided'
        });
    }

    //get user from mongo db
    const user = await client.db(dbName).collection('users').find({uuid: token}).toArray();

    //return error if user not found
    if(user.length === 0){
        return res.status(400).json({
            message: 'User not found'
        });
    }

    //get email and wallet
    const {email, wallet} = user[0];

    return res.status(200).json({
        message: 'User validated successfully',
        state: true,
        wallet: wallet,
        email: email,
        token: token
    });
});

app.post('/api/refresh', async (req, res) => {

    if (!req.body.token) {
        return res.status(401).json({
            message: 'No token provided'
        });
    }

    const { token } = req.body;


    try {
        const { data } = jwt.verify(token, process.env.TOKEN_SECRET);

        let user = await client.db(dbName).collection('users').find({uuid: data}).toArray();

        if(!user || user.length === 0) {
            return res.status(400).json({
                message: 'User does not exist'
            });
        }

        user = user[0];
        const newToken = jwt.sign({
            data: user.uuid,
        }, process.env.TOKEN_SECRET, {
            expiresIn: '1h'
        });

        return res.status(200).json({
            message: 'Token refreshed successfully',
            token: newToken
        });
    } catch (error) {
        return res.status(500).json({
            message: `Something went wrong: ${error}`
        });
    }

});

app.get('/api/kyc', async (req, res) => {
    //get token from header
    const token = req.headers.token;

    //get user from mongo db
    const user = await client.db(dbName).collection('users').find({uuid: token}).toArray();

    //return error if user not found
    if(user.length === 0){
        return res.status(400).json({
            message: 'User not found'
        });
    }

    //get email and wallet
    const {email, wallet} = user[0];

    let type = 'queryAllAccounts';
    await getKyc(type, res);
});

app.get('/api/admin_customers', async (req, res) => {
    let type = 'queryAllAccounts';
    await getCustomer(type, res);
});

app.post('/api/admin_kyc_action', (req, res)=>{
    //get token from header
    const token = req.headers.token;

    //throw error if token is not present
    if(!token){
        return res.status(401).json({
            message: 'No token provided'
        });
    }

    //get user from mongo db
    const user = client.db(dbName).collection('admin').find({uuid: token}).toArray();

    //return error if user not found
    if(user.length === 0){
        return res.status(400).json({
            message: 'User not found'
        });
    }

    return res.status(200).json({response: 'result.toString()'});
});

app.get('/api/admin_kyc', async (req, res) =>{
    let type = 'queryAllAccounts';
    await getKyc(type, res);
});


function base64_encode(file, mimetype) {
    return `data:${mimetype};base64,` + fs.readFileSync(file, 'base64');
}

app.post('/api/kyc', upload.any(), async (req, res) => {

    //get token from header
    const token = req.headers.token;

    //throw error if token is not present
    if(!token){
        return res.status(401).json({
            message: 'No token provided'
        });
    }

    //get user from mongo db
    const user = await client.db(dbName).collection('users').find({uuid: token}).toArray();

    //throw error if user not found
    if(user.length === 0){
        return res.status(400).json({
            message: 'User not found'
        });
    }

    // get wallet from user
    const {wallet} = user[0];

    let proofOfRes = base64_encode(req.files[0].path, req.files[0].mimetype);
    let proofOfId = base64_encode(req.files[1].path, req.files[1].mimetype);

    let userData = {
        firstname: req.body.firstname,
        proofOfResidence: proofOfRes,
        proofOfId: proofOfId,
        owner: wallet
    };

    await saveKyc(res, 'kyc', 'channel', userData);

    return res.status(200).json({
        message: 'Kyc Successfully saved'
    });

});


app.listen(8081, '0.0.0.0');
console.log('Running on http://0.0.0.0:8081');
