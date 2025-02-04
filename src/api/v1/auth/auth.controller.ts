import { Body, Controller, Get, Param, Post, Put, Delete, HttpCode, Patch, Res, Req, HttpException, HttpStatus } from '@nestjs/common';
import { Response, Request } from 'express';
import { AuthService } from './auth.service';
import { SignUpDto } from './dto/signup.dto';
import { OtpService } from './otp_verification/otp_verification.service';
import { UpdateUserDto } from './dto/updateUser.dto';
import { ApiResponse } from '../../../interfaces/response.interface';
import { ForgotPasswordDto, ResetPasswordDto } from './dto/password.dto';
import { JwtPayload } from 'src/interfaces/jwt-payload.interface';
import e from 'express';
import { JwtService } from './jwt/jwt.service';
import { JwtValidationService } from '../jwt-validation/jwt-validation.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService, private readonly otpService: OtpService, private readonly jwtService:JwtService,private readonly jwtValidationService:JwtValidationService) {}

  @Get('users')
  async getAllUsers(): Promise<ApiResponse<any>> {
    return this.authService.getAllUsers();
  }

  @Post('signUp')
  @HttpCode(201)
  async signUp(@Body() signUpDto: SignUpDto): Promise<ApiResponse<any>> {
    return this.authService.signUp(signUpDto);
  }

  // @Post('signIn')
  // @HttpCode(200)
  // async login(@Body() user: { email: string; password: string }, @Res() res: Response, @Req() req:Request): Promise<any> {
  
  //   const response = await this.authService.login(user);
  //   // console.log(response.refreshToken);
    
  //   await this.jwtService.storeRefreshToken(response.userId, response.refreshToken, req);
  //   res.cookie("refresh_token", response.refreshToken, {
  //     httpOnly: true,
  //     secure: true,
  //     sameSite: "strict",
  //     maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  //   });
  //   // delete response.data.refresh_token;
  //   console.log(response);
  //   return response;
  // }

  @Post('signIn')
  @HttpCode(200)
  async login(@Body() body: any, @Res() res: Response){
    const response = await this.authService.login(body);
    await this.jwtService.storeRefreshToken(response.userId, response.refreshToken, body.req);

    res.cookie("refresh_token", response.refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 100 * 1000, // 7 days
    });

    return res.json({
      UserId: response.userId,
      accessToken: response.accessToken,
    });
  }

  @Put('user/:id')
  async updateUser(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto): Promise<ApiResponse<any>> {
    return this.authService.updateUser(id, updateUserDto);
  }

  @Delete('user/:id')
  @HttpCode(204)
  async deleteUser(@Param('id') id: string): Promise<ApiResponse<any>> {
    return this.authService.deleteUser(id);
  }

  @Patch('change-password')
  async changePassword(
    @Body() body: { email: string; oldPassword: string; newPassword: string }
  ) {
    return this.authService.changePassword(body.email, body.oldPassword, body.newPassword);
  }
  @Post('forgot-password')
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto): Promise<ApiResponse<any>> {
    return this.authService.forgotPassword(forgotPasswordDto.email);
  }

  @Post('reset-password')
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto): Promise<ApiResponse<any>> {
    return this.authService.resetPassword(resetPasswordDto.token, resetPasswordDto.newPassword);
  }

  @Post('refresh')
  async refreshToken(@Req() req: Request, @Res() res: Response) {
    const refreshToken = req.cookies['refresh_token'];
    if (!refreshToken) throw new HttpException('Refresh token required', HttpStatus.FORBIDDEN);

    try {
      const { userId, email } = await this.jwtValidationService.validateToken(refreshToken);

      const { accessToken, refreshToken: newRefreshToken } =
        await this.jwtService.validateRefreshToken(userId,email, refreshToken, req);

      res.cookie('refresh_token', newRefreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      return res.json({ accessToken });
    } catch {
      throw new HttpException('Invalid or expired refresh token', HttpStatus.UNAUTHORIZED);
    }
  }

  @Post('logout')
  async logout(@Body() body: any, @Res() res: Response) {
    // console.log(body.userId);
    try{
      await this.authService.logout(body.userId);

      res.clearCookie('refresh_token', {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
      });
      return res.status(200).json({ message: 'Logged out successfully' });
    }
    catch(error){
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
}
