import { IsEmail, IsOptional, IsString, MinLength, IsBoolean } from 'class-validator';

export class SignUpDto {
  @IsEmail()
  email: string;

  @IsString()
  country: string;

  @IsString()
  @MinLength(6)
  password: string;

  @IsOptional()
  @IsBoolean()
  isEnabled?: boolean;

  @IsOptional()
  @IsString()
  refreshToken?: string;
}
