import { Injectable } from '@nestjs/common';
import { BufferSource } from 'node:stream/web';

@Injectable()
export abstract class HashingService {
  abstract hash(data: string | Buffer): Promise<string>;
  abstract compare(
    data: string | BufferSource,
    encrypted: string,
  ): Promise<boolean>;
}
