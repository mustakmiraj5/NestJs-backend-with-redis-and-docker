import { Injectable, ConflictException, UnauthorizedException, HttpStatus, HttpException } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { SignUpDto } from './dto/signup.dto';
import { JwtService } from './jwt/jwt.service';
import { LoginDto } from './dto/login.dto';
import { UpdateUserDto } from './dto/updateUser.dto';
import { JwtPayload } from '../../../interfaces/jwt-payload.interface';
import { ApiResponse } from '../../../interfaces/response.interface';
import { createResponse } from '../../../utils/response.helper';
import * as nodemailer from 'nodemailer';
import {OtpService} from './otp_verification/otp_verification.service';
import { EmailService } from './email.service';
import * as crypto from 'crypto'
import { PrismaService } from 'prisma/prisma.service';

@Injectable()
export class AuthService {

  constructor(
    private readonly jwtService: JwtService ,
    private readonly OtpService:OtpService,
    private readonly Emailservice:EmailService,
    private readonly prisma: PrismaService
    ) {}

  // async onModuleDestroy() {
  //   await this.prisma.$disconnect();
  // }
  // Placeholder Method
  getHello(): string {
    return 'Hello World!';
  }


  async getAllUsers(): Promise<ApiResponse<any>> {
    const users = await this.prisma.user.findMany();
    return createResponse('Users retrieved successfully', true, { users });
  }


  // Sign up a new user
  async signUp(signUpDto: SignUpDto): Promise<ApiResponse<any>> {
    const { email, country, password } = signUpDto;

    const existingUser = await this.prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      throw new ConflictException('User with this email already exists'); // Returns 409 Conflict
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await this.prisma.user.create({
      data: {
        email,
        country,
        password: hashedPassword,
        isEnabled: false,
        refreshTokens: '',
      },
    });

    // return createResponse('User created successfully', true, { user: newUser }, HttpStatus.CREATED); // 201 Created
    return createResponse('User created successfully', true, { user: newUser }, HttpStatus.CREATED); // 201 Created
  }

  // Update user verification status
  async updateUserVerificationStatus(email: string, isEnabled: boolean) {
    await this.prisma.user.update({ where: { email }, data: { isEnabled } });
  }

  // Login user
  async login(loginDto: LoginDto): Promise<any> {
    const { email, password } = loginDto;
    const existingUser = await this.validateUser(email, password);
    if (!existingUser) {
      throw new UnauthorizedException('Invalid credentials'); // Returns 401 Unauthorized
      }

    // Update the logged_at field with the current timestamp
    await this.prisma.user.update({
      where: { email },
      data: { last_logged_at: new Date() }, // Set the login timestamp
    });
    console.log('User logged in successfully');

    // Generate access and refresh tokens
      const accessToken = this.jwtService.generateAccessToken({ id: existingUser.id, email });
      const refreshToken = this.jwtService.generateRefreshToken(existingUser.id);

    //descructed the user object to remove the password field and add some other fields
    const userData ={
      id:existingUser.id,
      country:existingUser.country,
    }

    // console.log(userData);
    // return createResponse('Login successful', true, { user: userData, access_token: accessToken,refresh_token: refreshToken });
    return {userId:existingUser.id, accessToken, refreshToken};
  }

  async validateUser(email: string, password: string): Promise<any> {
    const existingUser = await this.prisma.user.findUnique({ where: { email } },);

    if (!existingUser || !(await bcrypt.compare(password, existingUser.password))) {
      throw new UnauthorizedException('Invalid credentials'); // Returns 401 Unauthorized
    }

    if (!existingUser.isEnabled) {
      throw new UnauthorizedException('Account not verified'); // Returns 401 Unauthorized
    }

    return existingUser;
  }

  // Update user
  async updateUser(id: string, updateUserDto: UpdateUserDto): Promise<ApiResponse<any>> {
    const updatedUser = await this.prisma.user.update({ where: { id }, data: updateUserDto });
    return createResponse('User updated successfully', true, { user: updatedUser }, HttpStatus.OK);
  }
  // Delete user
  async deleteUser(id: string): Promise<ApiResponse<any>> {
    const user = await this.prisma.user.findUnique({ where: { id } });

    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND); // Returns 404 Not Found
    }

    await this.prisma.user.update({ where: { id }, data: { isDeleted: true } });
    return createResponse('User deleted successfully', true, null, HttpStatus.ACCEPTED); // 204 No Content
  }

  //update user password

  async changePassword(email: string, oldPassword: string, newPassword: string) : Promise<ApiResponse<any>>  {
    const user = await this.prisma.user.findUnique({ where: { email } });

    if (!user) {
      return createResponse('User not found', false, null, HttpStatus.NOT_FOUND);
    }

    // Compare old password
    const isPasswordValid = await bcrypt.compare(oldPassword, user.password);
    if (!isPasswordValid) {
      return createResponse('Incorrect old password', false, null, HttpStatus.UNAUTHORIZED);
    }

    // Hash the new password and update it
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await this.prisma.user.update({
      where: { email },
      data: { password: hashedPassword },
    });

    return createResponse('Password changed successfully', true, null, HttpStatus.OK);
  }

  // Forgot password
  async forgotPassword(email: string): Promise<ApiResponse<any>> {
    const user = await this.prisma.user.findUnique({ where: { email } });

    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    // Generate a secure token and expiry time
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpiry = new Date(Date.now() + 3600000); // 1 hour

    // Save token and expiry in the database
    await this.prisma.user.update({
      where: { email },
      data: { resetToken, resetTokenExpiry },
    });

    // Send reset link via email
    const resetLink = `http://yourfrontend.com/reset-password?token=${resetToken}`;
    await this.Emailservice.sendResetPasswordEmail(email, resetLink);

    return createResponse('Password reset link sent to your email', true);
  }

  //reset password
  async resetPassword(token: string, newPassword: string): Promise<ApiResponse<any>> {
    const user = await this.prisma.user.findFirst({
      where: {
        resetToken: token,
        resetTokenExpiry: { gt: new Date() }, // Check token validity
      },
    });

    if (!user) {
      throw new HttpException('Invalid or expired token', HttpStatus.BAD_REQUEST);
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password and clear reset token
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        resetToken: null,
        resetTokenExpiry: null,
      },
    });

    return createResponse('Password reset successfully', true);
  }

  async logout(userId: string){
    try{
      await this.prisma.user.update({
        where: { id: userId },
        data: { refreshTokens: null }, // Clearing stored refresh tokens
      });

      return { message: 'Logged out successfully' };
    }
    catch(error){
      throw new Error('Could not log out');;
    }
  }

}