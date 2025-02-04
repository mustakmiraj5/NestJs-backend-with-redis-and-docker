import { Controller, Post, Body, Get } from '@nestjs/common';
import { OtpService } from './otp_verification.service';
import { GenerateOtpDto } from './dtos/generate-otp.dto';
import { VerifyOtpDto } from './dtos/verify-otp.dto';
import { AuthService } from '../auth.service';
import { createResponse } from '../../../../utils/response.helper';
import { ApiResponse } from '../../../../interfaces/response.interface';

@Controller('auth/otp')
export class OtpController {
  constructor(
    private readonly otpService: OtpService,
    private readonly authService: AuthService
  ) {}

  @Get()
  getHello() {
    return createResponse('Hello World!', true);
  }

  @Post('send-otp')
  async generateOtp(@Body() generateOtpDto: GenerateOtpDto): Promise<ApiResponse<any>> {
    const { email } = generateOtpDto;

    try {
      // Generate OTP and send it to email
      const otp = await this.otpService.generateOtp(email);
      await this.otpService.sendOtpToEmail(email, otp);

      return createResponse('OTP sent to email', true, null);
    } catch (error) {
      return createResponse('Failed to generate or send OTP', false);
    }
  }

  @Post('verify-otp')
  async verifyOtp(@Body() verifyOtpDto: VerifyOtpDto) {
    const { email, otp } = verifyOtpDto;
    const response = await this.otpService.verifyOtp(email, otp);

    if (response.success) {
      await this.authService.updateUserVerificationStatus(email, true);
    }

    return response;
  }

}