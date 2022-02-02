var express = require('express');
var cors = require('cors')
var app = express();


const uuid = require('uuid');
const fabricUser = require('./registerUserAPI');
const bcrypt = require('bcryptjs')
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const { MongoClient } = require('mongodb');

dotenv.config();

app.use(cors({
    origin: '*'
}))

app.use(express.json());
app.use(express.urlencoded({ extended: false })) // for parsing application/x-www-form-urlencoded


// Setting for Hyperledger Fabric
const { Wallets, FileSystemWallet, Gateway } = require('fabric-network');
const path = require('path');
const fs = require('fs');

const ccpPath = path.resolve(__dirname, '..',  'config','connection-profile','org1-network.json');
const ccp = JSON.parse(fs.readFileSync(ccpPath, 'utf8'));


const uri = "mongodb://root:1234@localhost:27017/?authSource=admin&readPreference=primary&appname=MongoDB%20Compass&ssl=false";

const client = new MongoClient(uri);
const dbName = 'test';

client.connect();
console.log('Connected successfully to server');

app.get('/api/kyc', async function (req, res) {
    try {
        // Create a new file system based wallet for managing identities.
        const walletPath = path.join(process.cwd(), 'wallet');
        const wallet = await Wallets.newFileSystemWallet(walletPath);
        console.log(`Wallet path: ${walletPath}`);

        // Check to see if we've already enrolled the user.
        const userExists = await wallet.get('appUser');
        if (!userExists) {
            console.log('An identity for the user "appUser" does not exist in the wallet');
            console.log('Run the registerUser.js application before retrying');
            return;
        }

        // Create a new gateway for connecting to our peer node.
        const gateway = new Gateway();
	    await gateway.connect(ccp, { wallet, identity: 'appUser', discovery: { enabled: true, asLocalhost: true } });

        // Get the network (channel) our contract is deployed to.
        const network = await gateway.getNetwork('mychannel');

        // Get the contract from the network.
        const contract = network.getContract('kyc_account');

        // Evaluate the specified transaction.
        const result = await contract.evaluateTransaction('queryAllAccounts');
        console.log(`Transaction has been evaluated, result is: ${result.toString()}`);
        res.status(200).json({response: result.toString()});

    } catch (error) {
        console.error(`Failed to evaluate transaction: ${error}`);
        res.status(500).json({error: error});
        process.exit(1);
    }
});

app.post('/api/createcustomer/', async function (req, res) {
    try {

        // Create a new file system based wallet for managing identities.
        const walletPath = path.join(process.cwd(), 'wallet');
        const wallet = await Wallets.newFileSystemWallet(walletPath);
        console.log(`Wallet path: ${walletPath}`);

        // Check to see if we've already enrolled the user.
        const userExists = await wallet.get('appUser');
        if (!userExists) {
            console.log('An identity for the user "appUser" does not exist in the wallet');
            console.log('Run the registerUser.js application before retrying');
            return;
        }

        // Create a new gateway for connecting to our peer node.
        const gateway = new Gateway();
        await gateway.connect(ccp, { wallet, identity: 'appUser', discovery: { enabled: true, asLocalhost: true } });

        // Get the network (channel) our contract is deployed to.
        const network = await gateway.getNetwork('mychannel');;

        // Get the contract from the network.
        const contract = network.getContract('fabcar');

        // Submit the specified transaction.
        await contract.submitTransaction('createProduct', req.body.productnumber, req.body.brand, req.body.price, req.body.count);
        console.log('Transaction has been submitted');
        res.send('Transaction has been submitted');

        // Disconnect from the gateway.
        await gateway.disconnect();

    } catch (error) {
        console.error(`Failed to submit transaction: ${error}`);
        process.exit(1);
    }
})

app.post('/api/register', async (req, res) => {
    try {
        //find user in database
    
        let user = await client.db(dbName).collection('users').find({email: req.body.email}).toArray();

        console.log(user)

        if (user.length > 0) {
            return res.status(400).json({
                message: `User with email ${req.body.email} already exists`
            })
        } else {
            
            const UUID = uuid.v4();
            let fabRes = await fabricUser.Enroll(UUID);
            console.log("Fab", fabRes);

            const {password} = req.body
            const salt = bcrypt.genSaltSync(10);
            req.body.password = bcrypt.hashSync(password, salt);
            req.body.uuid = UUID;
            req.body.email = req.body.email.toLowerCase();

            let user = await client.db(dbName).collection('users').insertOne(req.body)

            return res.status(200).json({
                message: 'User created successfully',
                user: user
            })
        }
    } catch (error) {
        
        return res.status(500).json({
            message: `Something went wrong: ${error}`
        })

    }

})

app.post('/api/login', async (req, res) => {
    const { email, password} = req.body;

    try {

        let user = await client.db(dbName).collection('users').find({email}).toArray();

        if(user.length > 0) {
            user = user[0];
            if(bcrypt.compareSync(password, user.password)) {
                const token = jwt.sign({
                    data: user.uuid,
                }, process.env.TOKEN_SECRET, {
                    expiresIn: '1h'
                });

                return res.status(200).json({
                    message: 'User logged in successfully',
                    token: token
                })
            } else {
                return res.status(400).json({
                    message: 'Incorrect password'
                })
            }
        } else {
            return res.status(400).json({
                message: 'User does not exist'
            })
        }
    } catch (error) {
        return res.status(500).json({
            message: `Something went wrong: ${error}`
        })
    }
})

//refresh token
app.post('/api/refresh', async (req, res) => {
    
    if (!req.body.token) {
        return res.status(401).json({
            message: 'No token provided'
        })
    }

    const { token } = req.body;
    

    try {
        const { data } = jwt.verify(token, process.env.TOKEN_SECRET);

        let user = await client.db(dbName).collection('users').find({uuid: data}).toArray();

        if(!user || user.length === 0) {
            return res.status(400).json({
                message: 'User does not exist'
            })
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
        })
    } catch (error) {
        return res.status(500).json({
            message: `Something went wrong: ${error}`
        })
    }

})

app.post('/api/invoke', (req, res, next) => {
    const { token } = req.body;

    jwt.verify(token, process.env.TOKEN_SECRET, (err, decoded) => {
        if(err){
            return res.status(401).json({
                message: 'Invalid token'
            })
        }

        const { email } = decoded.data;

        User.findOne({email}, async (err, user) => {
            if(err){
                return res.status(500).json({
                    message: 'Error finding user'
                })
            }

            if(!user){
                return res.status(401).json({
                    message: 'Invalid token'
                })
            }

            //get uuid from user
            const { uuid } = user;

            try {
                // load the network configuration
                const ccpPath = path.resolve(__dirname, '..',  'config','connection-profile','org1-network.json');
                let ccp = JSON.parse(fs.readFileSync(ccpPath, 'utf8'));
        
                // Create a new file system based wallet for managing identities.
                const walletPath = path.join(process.cwd(), 'wallet');
                const wallet = await Wallets.newFileSystemWallet(walletPath);
                console.log(`Wallet path: ${walletPath}`);
        
                // Check to see if we've already enrolled the user.
                const identity = await wallet.get(uuid);
                if (!identity) {
                    console.log('An identity for the user "appUser" does not exist in the wallet');
                    console.log('Run the registerUser.js application before retrying');
                    return;
                }
        
                // Create a new gateway for connecting to our peer node.
                const gateway = new Gateway();
                await gateway.connect(ccp, { wallet, identity: uuid, discovery: { enabled: true, asLocalhost: true } });
        
                // Get the network (channel) our contract is deployed to.
                const network = await gateway.getNetwork('mychannel');
        
                // Get the contract from the network.
                const contract = network.getContract('fabcar');
        
                await contract.submitTransaction('createAccount', '', '', '', '');
                console.log('Transaction has been submitted');
        
                // Disconnect from the gateway.
                await gateway.disconnect();

                return res.status(200).json({
                    message: 'Transaction has been submitted'
                })
        
            } catch (error) {
                console.error(`Failed to submit transaction: ${error}`);
                
                return res.status(500).json({
                    message: 'Failed to submit transaction'
                })
            }
        })

        return res.status(200).json({
            message: 'Token verified'
        })
    })
    
})

// app.get('/api/account/:id', (req, res, next) => {
//     userServices.getById(req.params.id).then(
//         (user) => res.json(user)
//     ).catch(err => next(err))
// })

// app.put('/api/changeblacklistingstatus/:product_number', async function (req, res) {
//     try {

//         // Create a new file system based wallet for managing identities.
//         const walletPath = path.join(process.cwd(), 'wallet');
//         const wallet = await Wallets.newFileSystemWallet(walletPath);
//         console.log(`Wallet path: ${walletPath}`);

//         // Check to see if we've already enrolled the user.
//         const userExists = await wallet.get('appUser');
//         if (!userExists) {
//             console.log('An identity for the user "appUser" does not exist in the wallet');
//             console.log('Run the registerUser.js application before retrying');
//             return;
//         }

//         // Create a new gateway for connecting to our peer node.
//         const gateway = new Gateway();
//         await gateway.connect(ccp, { wallet, identity: 'appUser', discovery: { enabled: true, asLocalhost: true } });

//         // Get the network (channel) our contract is deployed to.
//         const network = await gateway.getNetwork('mychannel');;

//         // Get the contract from the network.
//         const contract = network.getContract('fabcar');

//         // Submit the specified transaction.
//         await contract.submitTransaction('changeProductPrice', req.params.product_number, req.body.price);
//         console.log('Transaction has been submitted');
//         res.send('Transaction has been submitted');

//         // Disconnect from the gateway.
//         await gateway.disconnect();

//     } catch (error) {
//         console.error(`Failed to submit transaction: ${error}`);
//         process.exit(1);
//     }	
// })

app.listen(8081, '0.0.0.0');
console.log('Running on http://0.0.0.0:8081');
