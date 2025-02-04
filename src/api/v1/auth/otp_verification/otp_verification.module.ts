import { Module,forwardRef } from '@nestjs/common';
import {OtpService} from './otp_verification.service';
import {OtpController} from './otp_verification.controller';
import { AuthModule } from '../auth.module';
import { EmailService } from '../email.service';

@Module({
  imports: [forwardRef(() => AuthModule)],
  controllers: [OtpController],
  providers: [OtpService,EmailService],
  exports: [OtpService],
})
export class Otp_verificationModule {}
