import { IsEmail, IsInt, Min, Max, isNotEmpty } from 'class-validator';

export class VerifyOtpDto {
  @IsEmail({}, { message: 'Invalid email address' })
  email: string;

  @IsInt({ message: 'OTP must be an integer' })
  @Min(100000, { message: 'OTP must be a 6-digit number' })
  @Max(999999, { message: 'OTP must be a 6-digit number' })
  otp: number;
}
