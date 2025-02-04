import { Injectable, Inject, BadRequestException } from '@nestjs/common';
import * as svgCaptcha from 'svg-captcha';
import { v4 as uuidv4 } from 'uuid';
import Redis from 'ioredis';

@Injectable()
export class CaptchaService {
  private redis: Redis;
  constructor() {
    this.redis = new Redis({
      host: 'dsdp-core-redis',
      port: 6379,
    });
  }


    async generateCaptcha(): Promise<{ key: string; captchaValue: string }> {
        const captcha = svgCaptcha.create({
          size: 6, // or 8 for longer CAPTCHA
          noise: 3,
          color: true,
          background: '#f4f4f4',
        });

        const key = `captcha-${uuidv4()}`; // Generate unique key
        // console.log(captcha.text);
        await this.redis.set(key, captcha.text, 'EX',300); // Store in Redis for 5 minutes

        // console.log(`Generated CAPTCHA: ${captcha.text}`);
         return { key, captchaValue: captcha.text };
    }

    async validateCaptcha(key: string, userInput: string): Promise<boolean> {
        // console.log(key);
        const storedCaptcha = await this.redis.get(key);

        // console.log(`Stored CAPTCHA: ${storedCaptcha}`);
        // const x = await this.redis.get('hi');
        // console.log(x);
        if (!storedCaptcha) {
          return false;
        }
        const isValid = storedCaptcha === userInput;
        if (isValid) {
            await this.redis.del(key); // Remove from Redis after validation
        }
            return isValid;
    }


}
