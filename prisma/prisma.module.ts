import { Global, Module } from '@nestjs/common';
import { PrismaService } from './prisma.service';

@Global()  // This makes the module globally available
@Module({
  providers: [PrismaService],
  exports: [PrismaService], // Expose PrismaService to be used in other parts of the module
})
export class PrismaModule {}
