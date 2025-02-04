import { BadRequestException, Body, Controller, Get, Post, UseInterceptors } from '@nestjs/common';
import { CaptchaService } from './captcha.service';

@Controller('captcha')
export class CaptchaController {
    constructor(private readonly captchaService: CaptchaService) {}
    // Utility method for consistent response format
  private formatResponse(
    statusCode: number,
    message: string,
    success: boolean,
    data: any = null,
) {
      return { status_code: statusCode, message, success, data };
}

    @Get('generate')
    // @UseInterceptors(CacheInterceptor)
    async getCaptcha() {
    const data = await this.captchaService.generateCaptcha();
    return this.formatResponse(200, 'CAPTCHA generated successfully', true, data);
  }

  @Post('verify')
  async verifyCaptcha(@Body() body: { key: string; answer: string }) {
    // console.log(body);
    const isValid = await this.captchaService.validateCaptcha(body.key, body.answer);
    // console.log(isValid);
    if (!isValid) {
      return this.formatResponse(400, 'CAPTCHA verification failed', false, null);
    }
    return this.formatResponse(200, 'CAPTCHA verification successful', true, null);
  }
}
