import { Controller, Get, Header, NotFoundException, Param } from '@nestjs/common';
import { StatusListService } from './status-list.service';
import { STATUS_LIST_ID } from './status-list.codec';

/** Serves the Token Status List Token (IETF draft-ietf-oauth-status-list §8). Public, CORS-enabled. */
@Controller('status-lists')
export class StatusListController {
  constructor(private readonly statusList: StatusListService) {}

  /** `GET /wp/status-lists/:id` → the signed `statuslist+jwt` (§8.2). */
  @Get(':id')
  @Header('content-type', 'application/statuslist+jwt')
  async get(@Param('id') id: string): Promise<string> {
    if (id !== STATUS_LIST_ID) throw new NotFoundException('unknown status list');
    return this.statusList.issueToken(id);
  }
}
