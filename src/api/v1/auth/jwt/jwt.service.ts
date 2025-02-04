import { Injectable, UnauthorizedException } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { Request } from 'express';
import { PrismaService } from 'prisma/prisma.service';

@Injectable()
export class JwtService {
  private readonly privateKey: string;
  private readonly publicKey: string;
  private readonly jwtExpiration = '12h';
  private readonly refreshTokenExpiration = '7d';

  constructor(private configService: ConfigService, private readonly prisma: PrismaService) {
    // Use the ConfigService to load keys
    this.privateKey = this.configService.get<string>('JWT_SECRET') ?? (() => { throw new Error('JWT_SECRET is not defined'); })();
    this.publicKey = this.configService.get<string>('JWT_PUBLIC_KEY') ?? (() => { throw new Error('JWT_PUBLIC is not defined'); })();
    // Load from .env
  }

  // Generate Access & Refresh Tokens
  generateAccessToken(user: { id: string; email: string }):string {
    if (!this.privateKey) {
      throw new Error('Private key is not provided');
    }

    const payload = {
      id: user.id,
      email: user.email,
    };

    return jwt.sign(payload, this.privateKey, { algorithm: 'RS256', expiresIn: this.jwtExpiration });
  }
  generateRefreshToken(payload: any) {
    if (!this.privateKey) {
      throw new Error('Private key is not provided');
    }

    const refreshToken = jwt.sign({payload}, this.privateKey, { algorithm: 'RS256', expiresIn: this.refreshTokenExpiration});
    // console.log(refreshToken);
    return refreshToken;
  }

  // Hash Data (For Secure Refresh Token Storage)
  async hashData(data: string) {
    return await bcrypt.hash(data, 10);
  }

  
  // Store Refresh Token in Database
  async storeRefreshToken(userId: string, refreshToken: string, req: Request) {
    // Hash the token
    const hashedToken = await this.hashData(refreshToken);
    // Store the hashed token
    await this.prisma.user.update({
      where: {
        id: userId, // Find the user by their ID
      },
      data: {
        refreshTokens: hashedToken, // Store the hashed refresh token
      },
    });
    console.log("Database updated!");
  }

    // Validate and rotate refresh tokens
    async validateRefreshToken(userId: string,email:string, refreshToken: string, req: Request) {
  
      const prevToken = await this.prisma.user.findUnique({ where: { id: userId }});
        if (prevToken?.refreshTokens && await bcrypt.compare(refreshToken, prevToken.refreshTokens)) {
  
          // Generate new tokens & rotate refresh token
          const refreshToken = await this.generateRefreshToken(userId);
          const accessToken = await this.generateAccessToken({ id: userId, email });
  
          
  
          return { accessToken, refreshToken: refreshToken };
        }
      
  
      throw new UnauthorizedException('Invalid refresh token');
    }
    


  
  
}

