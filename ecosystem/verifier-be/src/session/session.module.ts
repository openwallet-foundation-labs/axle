import { Global, Module } from '@nestjs/common';
import { SessionStore } from './session.store';

@Global()
@Module({
  providers: [SessionStore],
  exports: [SessionStore],
})
export class SessionModule {}
