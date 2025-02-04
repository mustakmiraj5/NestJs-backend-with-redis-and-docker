import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { JwtValidationService } from './jwt-validation.service';

// console.log(process.env.JWT_PUBLIC_KEY);
// console.log(process.env.JWT_SECRET);
@Module({
    imports: [
      JwtModule.register({
        publicKey: process.env.JWT_PUBLIC_KEY, // Load public key from .env
      }),
    ],
    providers: [JwtValidationService],
    exports: [JwtValidationService],
  })
  export class JwtValidationModule {}