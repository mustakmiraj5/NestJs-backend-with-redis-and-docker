import { HttpStatus } from '@nestjs/common';
import { ApiResponse } from '../interfaces/response.interface';

export const createResponse = <T>(
  message: string,
  success: boolean,
  data?: T,
  statusCode: number = success ? HttpStatus.OK : HttpStatus.BAD_REQUEST
): ApiResponse<T> => ({
  statusCode,
  message,
  success,
  data,
});
