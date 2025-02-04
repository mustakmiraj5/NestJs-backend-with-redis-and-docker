import { forwardRef, Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtModule } from './jwt/jwt.module';
import { Otp_verificationModule } from './otp_verification/otp_verification.module';
import { OtpService } from './otp_verification/otp_verification.service';
import { EmailService } from './email.service';
import { JwtValidationModule } from '../jwt-validation/jwt-validation.module';

@Module({
  imports: [forwardRef(() => Otp_verificationModule),JwtModule, JwtValidationModule],
  controllers: [AuthController],
  providers: [AuthService,OtpService,EmailService],
  exports: [AuthService],
})
export class AuthModule {}
