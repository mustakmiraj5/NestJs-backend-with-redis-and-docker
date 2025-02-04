import { Injectable, BadRequestException, InternalServerErrorException } from '@nestjs/common';
import { PrismaService } from '../../../../../prisma/prisma.service';
import * as nodemailer from 'nodemailer';
import { createResponse } from '../../../../utils/response.helper';
import { EmailService } from '../email.service';


@Injectable()
export class OtpService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly emailService: EmailService
  ) {}

  // Generate OTP and store it in the database
  async generateOtp(email: string): Promise<number> {
    const otp = Math.floor(100000 + Math.random() * 900000); // Generate 6-digit OTP
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // Set expiry time to 5 minutes

    try {
      await this.prisma.otp.create({
        data: { otp, email, expiresAt },
      });
      return otp;
    } catch (error) {
      throw new Error('Failed to generate OTP');
    }
  }
  // Send OTP to the user's email 1
  // async sendOtpToEmail(email: string, otp: number): Promise<void> {
  //   const transporter = nodemailer.createTransport({
  //     service: 'gmail',
  //     auth: {
  //       user: process.env.EMAIL_USER,
  //       pass: process.env.EMAIL_PASS,
  //     },
  //   });
  //
  //   const mailOptions = {
  //     from: process.env.EMAIL_USER,
  //     to: email,
  //     subject: 'Your OTP for Verification',
  //     text: `Your OTP is ${otp}. It will expire in 5 minutes.`,
  //     html: `<p>Your OTP is <b>${otp}</b>. It will expire in 5 minutes.</p>`,
  //   };
  //
  //   try {
  //     await transporter.sendMail(mailOptions);
  //   } catch (error) {
  //     throw new Error('Failed to send OTP email');
  //   }
  // }

  // Send OTP to the user's email 2
  async sendOtpToEmail(email: string, otp: number): Promise<void> {
    await this.emailService.sendOtpToEmail(email, otp);
  }

  async verifyOtp(email: string, otp: number) {
    const otpRecord = await this.prisma.otp.findFirst({
      where: { email, otp, expiresAt: { gte: new Date() } },
    });

    if (!otpRecord) {
      return createResponse('Invalid or expired OTP', false);
    }

    await this.prisma.otp.delete({ where: { id: otpRecord.id } });
    return createResponse('OTP verified successfully', true);
  }

}

