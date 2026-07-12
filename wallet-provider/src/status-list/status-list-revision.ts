import { Global, Injectable, Module } from '@nestjs/common';

/**
 * In-process signal bumped whenever instance revocation state changes, so the cached status list token is
 * rebuilt promptly on the same replica. Global (not owned by either the wallet-provider or status-list
 * module) to avoid a circular module dependency. Across replicas, the cache TTL bounds staleness.
 */
@Injectable()
export class StatusListRevision {
  private revision = 0;

  bump(): void {
    this.revision++;
  }

  get current(): number {
    return this.revision;
  }
}

@Global()
@Module({
  providers: [StatusListRevision],
  exports: [StatusListRevision],
})
export class StatusListRevisionModule {}
