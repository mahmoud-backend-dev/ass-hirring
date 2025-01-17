import path, { dirname } from 'path';
import { fileURLToPath } from 'url';
const __fileName = fileURLToPath(import.meta.url);
const __dirname = dirname(__fileName);
import 'express-async-errors';
import 'dotenv/config.js';
import express, { json, urlencoded, static as static_ } from 'express';
import MountApis from './routes/index.js'
const app = express();
const port = process.env.PORT || 1812;


// Setting Security For App
import cors from 'cors';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import hpp from 'hpp';
import mongoSanitize from 'express-mongo-sanitize';

import errorHandler from './middleware/error-handler.js';
import notFoundErr from './middleware/notFoundMiddleware.js';
import connectDB from './db/connectDB.js';


// Enable other domains to access your application
app.use(cors());
app.options('*', cors());

// Compress all responses
app.use(compression());


app.use(json());
app.use(urlencoded({ extended: true }));
app.use(static_(path.join(__dirname, 'uploads')));

// To remove data using these defaults, To apply data sanitization
// nosql mongo injection
app.use(mongoSanitize());



// Limit each IP to 100 requests per `window` (here, per 15 minutes)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,  // 15 minutes
    max: 100,
    message:
        'Too many accounts created from this IP, please try again after an 15 minutes'
})

// Apply the rate limiting middleware to all requests
app.use(limiter)


// Express middleware to protect against HTTP Parameter Pollution attacks
app.use(hpp())


// Mount Apis
MountApis(app);

app.use(errorHandler);
app.use(notFoundErr);

const start = async () => {
    try {
        await connectDB(process.env.URI);
        app.listen(port, () => console.log(`Listen server on http://localhost:${port}`));
    } catch (error) {
        console.log(error);
    }
};

start();