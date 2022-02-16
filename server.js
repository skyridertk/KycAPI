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

function generateToken(uuid) {
    const token = jwt.sign({
        data: uuid,
    }, process.env.TOKEN_SECRET, {
        expiresIn: '10h'
    });
    return token;
}

function handleLogin(userPassword, password, uuid, res) {
    try {
        if (bcrypt.compareSync(password, userPassword)) {
            const token = generateToken(uuid);

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

async function getKyc(my_contract, uuid) {
    let channel = "mychannel"

    try {
        let {ccp, wallet, identity} = await loadWallet(uuid);
        if (!identity) {
            console.log(`An identity for the user "${uuid}" does not exist in the wallet`)
            return false
        }

        const {gateway, contract} = await handleGateway(ccp, wallet, uuid, channel, my_contract);

        // Evaluate the specified transaction.
        const result = await contract.evaluateTransaction('QueryAssetsByOwner', uuid);
        console.log(`Transaction has been evaluated, result is: ${result.toString()}`);

        await gateway.disconnect();

        return JSON.parse(result.toString())

    } catch (error) {
        console.error(`Failed to evaluate transaction: ${error}`);
        return false
    }
}

async function getPendingKyc(my_contract, uuid) {
    let channel = "mychannel"

    try {
        let {ccp, wallet, identity} = await loadWallet(uuid);
        if (!identity) {
            console.log(`An identity for the user "${uuid}" does not exist in the wallet`)
            return false
        }

        const {gateway, contract} = await handleGateway(ccp, wallet, uuid, channel, my_contract);

        // Evaluate the specified transaction.
        const result = await contract.evaluateTransaction('QueryAssetsByStatus', "pending");
        console.log(`Transaction has been evaluated, result is: ${result.toString()}`);

        await gateway.disconnect();

        return JSON.parse(result.toString())

    } catch (error) {
        console.error(`Failed to evaluate transaction: ${error}`);
        return false
    }
}

async function updateStatusKyc(my_contract, uuid, assetName, assetStatus) {
    let channel = "mychannel"

    console.log(assetName, assetStatus)

    try {
        let {ccp, wallet, identity} = await loadWallet(uuid);
        if (!identity) {
            console.log(`An identity for the user "${uuid}" does not exist in the wallet`)
            return false
        }

        const {gateway, contract} = await handleGateway(ccp, wallet, uuid, channel, my_contract);

        // Update Tranasction transaction.
        const result = await contract.submitTransaction('UpdateAsset', assetName, assetStatus);
        console.log(`Transaction has been evaluated, result is: ${result.toString()}`);

        await gateway.disconnect();

        return true

    } catch (error) {
        console.error(`Failed to evaluate transaction: ${error}`);
        return false
    }
}

async function getAllCustomers(my_contract, uuid) {
    let channel = "mychannel"

    try {
        let {ccp, wallet, identity} = await loadWallet(uuid);
        if (!identity) {
            console.log(`An identity for the user "${uuid}" does not exist in the wallet`)
            return false
        }

        const {gateway, contract} = await handleGateway(ccp, wallet, uuid, channel, my_contract);

        // Evaluate the specified transaction.
        const result = await contract.evaluateTransaction('queryAllAccounts', uuid);
        console.log(`Transaction has been evaluated, result is: ${result.toString()}`);

        await gateway.disconnect();

        return JSON.parse(result.toString())

    } catch (error) {
        //console.error(`Failed to evaluate transaction: ${error}`);
        return false
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
        const result = await contract.evaluateTransaction('queryAccount');
        console.log(`Transaction has been evaluated, result is: ${result.toString()}`);


        await gateway.disconnect();
        return res.status(200).json({response: result.toString()});

    } catch (error) {
        //console.error(`Failed to evaluate transaction: ${error}`);
        res.status(500).json({error: error});
    }
}

async function saveKyc(my_contract, userData, uuid) {
    let channel = "mychannel"

    try {
        let {ccp, wallet, identity} = await loadWallet(uuid);
        if (!identity) {

            console.log(`An identity for the user "${uuid}" does not exist in the wallet`)
            return false
        }

        const {gateway, contract} = await handleGateway(ccp, wallet, uuid, channel, my_contract);

        let result = await contract.submitTransaction('CreateAsset', userData.assetID, userData.firstname, userData.lastname,  userData.address, userData.dateOfBirth, userData.idNumber, userData.gender, userData.status,  userData.approvalCount, userData.owner, userData.proofOfResidence, userData.proofOfId);

        console.log('Transaction submitted: '+result.toString())

        await gateway.disconnect();
        return true

    } catch (error) {

        console.log("Failed to submit transaction: " + error)
        
        return false
    }
}

async function saveCustomer(my_contract, userData) {
    let channel = 'mychannel'
    let uuid = userData.uuid
    let email = userData.email
    let accountID = userData.id

    console.log(uuid)
    console.log(email)

    try {
        let {ccp, wallet, identity} = await loadWallet(uuid);
        if (!identity) {
            console.log(`An identity for the user "${uuid}" does not exist in the wallet`);
            return false;
        }

        const {gateway, contract} = await handleGateway(ccp, wallet, uuid, channel, my_contract);

        //submit transaction
        let resp = await contract.submitTransaction('createAccount', accountID, email, uuid);
        console.log("Transaction has been submitted: " + resp);

        await gateway.disconnect();

        return true;

    } catch (error) {
        console.error(`Failed to evaluate transaction: ${error}`);
        return false
    }
}


function base64_encode(file, mimetype) {
    return `data:${mimetype};base64,` + fs.readFileSync(file, 'base64');
}
//DONE
app.post('/api/register', async (req, res) => {
    const UUID_ID = require('uuid').v4();
    try {

        let user = await client.db(dbName).collection('users').find({email: req.body.email}).toArray();

        if (user.length > 0) {
            return res.status(400).json({
                message: `User with email ${req.body.email} already exists`
            });
        } else {

            const UUID = uuid.v4();
            await fabricUser.Enroll(UUID);

            const {password} = req.body;
            const salt = bcrypt.genSaltSync(10);
            req.body.password = bcrypt.hashSync(password, salt);
            req.body.uuid = UUID;
            req.body.email = req.body.email.toLowerCase();

            let user = await client.db(dbName).collection('users').insertOne(req.body);

            const token = generateToken(UUID)

            console.log("Here")
            console.log(req.body)

            let userdata = {
                id: UUID_ID,
                uuid: UUID,
                email: req.body.email,
            }

            let status = await saveCustomer('kyc_account', userdata);
            console.log(status)

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


//DONE
app.post('/api/login', async (req, res) => {

    const { email, password} = req.body;

    let user = await client.db(dbName).collection('users').find({email: email}).toArray();

    // if user not found
    if (user.length === 0) {
        return res.status(400).json({
            message: `User with email ${email} does not exist`
        });
    }

    //get user password
    const userPassword = user[0].password;

    //get user uuid
    const userUUID = user[0].uuid;

    return handleLogin(userPassword, password, userUUID, res);
});

//DONE
app.post('/api/admin_login', async (req, res) => {
    const { username, password} = req.body;

    let user = await client.db(dbName).collection('admin').find({username: username}).toArray();

    // if user not found
    if (user.length === 0) {
        return res.status(400).json({
            message: `User with username ${username} does not exist`
        });
    }

    //get user password
    const userPassword = user[0].password;

    //get user uuid
    const userUUID = user[0].uuid;

    return handleLogin(userPassword, password, userUUID, res);
});

//DONE
app.post('/api/admin_register', async (req, res) => {
    try {

        let user = await client.db(dbName).collection('admin').find({username: req.body.username}).toArray();

        if (user.length > 0) {
            return res.status(400).json({
                message: `User with username ${req.body.username} already exists`
            });
        } else {

            const UUID = uuid.v4();
            // await fabricUser.Enroll(UUID);

            const {password} = req.body;
            const salt = bcrypt.genSaltSync(10);
            req.body.password = bcrypt.hashSync(password, salt);
            req.body.uuid = UUID;
            req.body.username = req.body.username.toLowerCase();

            let user = await client.db(dbName).collection('admin').insertOne(req.body);

            const token = generateToken(UUID)

            console.log("Here")
            console.log(req.body)


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

//DONE
app.get('/api/admin_validate', async (req, res)=>{

    //token from header
    const token = req.headers.token;

    //throw error if token is not present
    if(!token){
        return res.status(401).json({
            message: 'No token provided'
        });
    }

    
    //decode token
    const decoded = jwt.verify(token, process.env.TOKEN_SECRET);

    const {data} = decoded;
    console.log(data)

    //get user from mongo db
    const user = await client.db(dbName).collection('admin').find({uuid: data}).toArray();

    //return error if user not found
    if(user.length === 0){
        return res.status(400).json({
            message: 'User not found'
        });
    }

    console.log(user)

    //get email and wallet
    const {username, uuid} = user[0];

    return res.status(200).json({
        message: 'User validated successfully',
        state: true,
        wallet: uuid,
        username: username,
        token: token
    });
});

//DONE
app.get('/api/validate', async (req, res)=>{

    //token from header
    const token = req.headers.token;
    console.log(token)

    //throw error if token is not present
    if(!token){
        return res.status(401).json({
            message: 'No token provided'
        });
    }

    
    //decode token
    const decoded = jwt.verify(token, process.env.TOKEN_SECRET);

    console.log(decoded)

    const {data} = decoded;
    console.log(data)

    //get user from mongo db
    const user = await client.db(dbName).collection('users').find({uuid: data}).toArray();

    //return error if user not found
    if(user.length === 0){
        return res.status(400).json({
            message: 'User not found'
        });
    }

    console.log(user)

    //get email and wallet
    const {email, uuid} = user[0];

    return res.status(200).json({
        message: 'User validated successfully',
        state: true,
        wallet: uuid,
        email: email,
        token: token
    });
});

//DONE
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

        let userUUID = user[0].uuid;
        const newToken = generateToken(userUUID);

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

//DONE
app.get('/api/kyc', async (req, res) => {
    //token from header
    const token = req.headers.token;

    //throw error if token is not present
    if(!token){
        return res.status(401).json({
            message: 'No token provided'
        });
    }
    
    //decode token
    const decoded = jwt.verify(token, process.env.TOKEN_SECRET);

    const {data} = decoded;
    console.log(data)

    //get user from mongo db
    const user = await client.db(dbName).collection('users').find({uuid: data}).toArray();

    //return error if user not found
    if(user.length === 0){
        return res.status(400).json({
            message: 'User not found'
        });
    }

    console.log(user)

    //get email and wallet
    const {username, uuid} = user[0];

    let dataKyc = await getKyc('kycChaincode', uuid)

    return res.status(200).json({
        message: 'Kycs',
        data: dataKyc
    });

});

//DONE
app.get('/api/admin_customers', async (req, res) => {
    //token from header
    const token = req.headers.token;

    //throw error if token is not present
    if(!token){
        return res.status(401).json({
            message: 'No token provided'
        });
    }

    
    //decode token
    const decoded = jwt.verify(token, process.env.TOKEN_SECRET);

    const {data} = decoded;
    console.log(data)

    //get user from mongo db
    const user = await client.db(dbName).collection('admin').find({uuid: data}).toArray();

    //return error if user not found
    if(user.length === 0){
        return res.status(400).json({
            message: 'User not found'
        });
    }

    console.log(user)

    //get email and wallet
    const {username, uuid} = user[0];
    
    let dataCustomers = await getAllCustomers('kyc_account', 'appUser');

    return res.status(200).json({
        message: 'Customers',
        data: dataCustomers
    });
});

app.post('/api/admin_kyc_action', async (req, res)=>{
    //token from header
    const token = req.headers.token;
    console.log(token)

    //throw error if token is not present
    if(!token){
        return res.status(401).json({
            message: 'No token provided'
        });
    }
    
    //decode token
    const decoded = jwt.verify(token, process.env.TOKEN_SECRET);

    console.log(decoded)

    const {data} = decoded;
    console.log(data)

    //get user from mongo db
    const user = await client.db(dbName).collection('admin').find({uuid: data}).toArray();

    //return error if user not found
    if(user.length === 0){
        return res.status(400).json({
            message: 'User not found'
        });
    }

    console.log(user)

    //get email and wallet
    const {email, uuid} = user[0];

    const {
        assetName,
        assetStatus
    } = req.body;

    console.log(req.body)

    let statusUpdate = await updateStatusKyc('kycChaincode', 'appUser', assetName, assetStatus)

    return res.status(200).json({
        message: 'Updated Status',
        status: statusUpdate
    });
});

//DONE
app.get('/api/admin_kyc', async (req, res) =>{
    //token from header
    const token = req.headers.token;

    //throw error if token is not present
    if(!token){
        return res.status(401).json({
            message: 'No token provided'
        });
    }
    
    //decode token
    const decoded = jwt.verify(token, process.env.TOKEN_SECRET);

    const {data} = decoded;
    console.log(data)

    //get user from mongo db
    const user = await client.db(dbName).collection('admin').find({uuid: data}).toArray();

    //return error if user not found
    if(user.length === 0){
        return res.status(400).json({
            message: 'User not found'
        });
    }

    console.log(user)

    //get email and wallet
    const {username, uuid} = user[0];

   
    let dataPending = await getPendingKyc('kycChaincode', 'appUser')

    return res.status(200).json({
        message: 'Kyc Pending',
        data: dataPending
    });
});

//DONE
app.post('/api/kyc', upload.any(), async (req, res) => {

    const UUID = require('uuid').v4();

    //token from header
    const token = req.headers.token;
    console.log(token)

    //throw error if token is not present
    if(!token){
        return res.status(401).json({
            message: 'No token provided'
        });
    }

    
    //decode token
    const decoded = jwt.verify(token, process.env.TOKEN_SECRET);

    console.log(decoded)

    const {data} = decoded;
    console.log(data)

    //get user from mongo db
    const user = await client.db(dbName).collection('users').find({uuid: data}).toArray();

    //return error if user not found
    if(user.length === 0){
        return res.status(400).json({
            message: 'User not found'
        });
    }

    console.log(user)

    //get email and wallet
    const {email, uuid} = user[0];

    let proofOfRes = base64_encode(req.files[0].path, req.files[0].mimetype);
    let proofOfId = base64_encode(req.files[1].path, req.files[1].mimetype);

    let userData = {
        assetID: UUID,
        firstname: req.body.firstname,
        lastname: req.body.lastname,
        dateOfBirth: req.body.dateOfBirth,
        gender: req.body.gender,
        status: req.body.status,
        address: req.body.address,
        idNumber: req.body.idNumber,
        approvalCount: 0,
        owner: uuid,
        proofOfResidence: proofOfRes,
        proofOfId: proofOfId,
    };

    console.log(userData)

    let status = await saveKyc('kycChaincode', userData, uuid);

    return res.status(200).json({
        message: 'Kyc Successfully saved',
        status: status
    });

});


app.listen(8084, '0.0.0.0');
console.log('Running on http://0.0.0.0:8084');
