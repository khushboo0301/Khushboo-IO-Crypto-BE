import { HttpStatus, Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response } from 'express';

@Injectable()
export class CustomThrottleMiddleware implements NestMiddleware {
    async use(req: Request, res: Response, next: () => void) {
        // Extract userId from request headers
        const userId = req.headers?.address?.toString();
        
        // Get the current timestamp
        const now = Date.now();
        
        // Get the request count object from app locals or initialize it if it doesn't exist
        const requestCount = req.app.locals.throttleCounter || {};
        
        // Initialize request count for the userId and originalUrl if it doesn't exist
        if (!requestCount[userId]) {
            requestCount[userId] = {};
        }
        if (!requestCount[userId][req.originalUrl]) {
            requestCount[userId][req.originalUrl] = {};
        }
        
        // Check if the time for the current userId and originalUrl is stored
        if (requestCount[userId][req.originalUrl]?.time) {
            let futureTime = requestCount[userId][req.originalUrl]["time"];
            futureTime = parseInt(futureTime);
            
            // If the current time is less than or equal to the future time, return TOO_MANY_REQUESTS status
            if (now <= futureTime) {
                return res
                    .status(HttpStatus.TOO_MANY_REQUESTS)
                    .json({statusCode: HttpStatus.TOO_MANY_REQUESTS, message: "Too Many Requests. Please Try after sometimes"});
            } else {
                // If the current time is greater than the future time, delete the stored time
                delete requestCount[userId][req.originalUrl];
                req.app.locals.throttleCounter = requestCount;
            }
        }
        
        // Proceed to the next middleware or controller
        next(); 
    }
    
}