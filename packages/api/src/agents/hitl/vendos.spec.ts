import { createHmac } from 'crypto';
import type { Agents } from 'librechat-data-provider';
import { attestVendosExecution, withVendosApproval, vendosApprovalHook } from './vendos';

const TOOL = 'execute_approved_change_mcp_vendos_pilot';
const KEY = 'synthetic-private-mcp-key-never-live';
const INPUT = {
  project: 'vendos-cz',
  plan_id: 'act-' + 'a'.repeat(20),
  plan_hash: 'b'.repeat(64),
  approval_summary: 'Přesná testovací změna – žádný skutečný zásah.',
};
const ACTION: Agents.PendingAction = {
  actionId: 'native-action',
  streamId: 'conversation',
  createdAt: Date.now(),
  payload: {
    type: 'tool_approval',
    action_requests: [{ name: TOOL, arguments: INPUT, tool_call_id: 'call-1' }],
    review_configs: [
      {
        action_name: TOOL,
        tool_call_id: 'call-1',
        allowed_decisions: ['approve', 'reject', 'edit'],
      },
    ],
  },
};
const APPROVE: Agents.ToolApprovalResolution[] = [{ tool_call_id: 'call-1', decision: 'approve' }];

describe('VENDOS native human-approval attestation', () => {
  it('always asks for this tool and allows only approve or reject', async () => {
    const input = {
      hook_event_name: 'PreToolUse' as const,
      runId: 'run',
      toolName: TOOL,
      toolInput: INPUT,
      toolUseId: 'call-1',
    };
    expect(await vendosApprovalHook(input, new AbortController().signal)).toMatchObject({
      decision: 'ask',
      allowedDecisions: ['approve', 'reject'],
    });
    expect(
      await vendosApprovalHook(
        { ...input, toolName: 'read_report_mcp_vendos_pilot' },
        new AbortController().signal,
      ),
    ).toEqual({});
  });
  it('leaves unrelated tools unchanged', () => {
    expect(
      attestVendosExecution('read_report_mcp_vendos_pilot', INPUT, 'owner', undefined, undefined),
    ).toBe(INPUT);
  });

  it('blocks model tool calls outside a claimed native approval resume', () => {
    expect(() => attestVendosExecution(TOOL, INPUT, 'owner', 'call-1', KEY)).toThrow(
      'click Approve',
    );
  });

  it('signs only exact owner, tool call and arguments, without exposing the key', async () => {
    await withVendosApproval(ACTION, APPROVE, 'owner', async () => {
      const result = attestVendosExecution(TOOL, INPUT, 'owner', 'call-1', KEY) as typeof INPUT & {
        approval_receipt: string;
      };
      const [body, signature] = result.approval_receipt.split('.');
      expect(signature).toBe(createHmac('sha256', KEY).update(body).digest('hex'));
      expect(JSON.parse(Buffer.from(body, 'base64url').toString())).toMatchObject({
        actor: 'librechat-owner',
        tool: TOOL,
        arguments: INPUT,
        nonce: 'native-action:call-1',
        v: 1,
      });
      expect(JSON.stringify(result)).not.toContain(KEY);
      expect(() => attestVendosExecution(TOOL, INPUT, 'owner', 'call-1', KEY)).toThrow(
        'click Approve',
      );
    });
    expect(() => attestVendosExecution(TOOL, INPUT, 'owner', 'call-1', KEY)).toThrow(
      'click Approve',
    );
  });

  it.each(['reject', 'edit', 'respond'] as const)(
    'does not turn %s into execution permission',
    async (decision) => {
      await withVendosApproval(
        ACTION,
        [{ tool_call_id: 'call-1', decision }],
        'owner',
        async () => {
          expect(() => attestVendosExecution(TOOL, INPUT, 'owner', 'call-1', KEY)).toThrow(
            'click Approve',
          );
        },
      );
    },
  );

  it('rejects different users, call IDs, missing private keys and changed summaries', async () => {
    await withVendosApproval(ACTION, APPROVE, 'owner', async () => {
      expect(() => attestVendosExecution(TOOL, INPUT, 'other', 'call-1', KEY)).toThrow();
      expect(() => attestVendosExecution(TOOL, INPUT, 'owner', 'different', KEY)).toThrow();
      expect(() => attestVendosExecution(TOOL, INPUT, 'owner', 'call-1', undefined)).toThrow();
      expect(() =>
        attestVendosExecution(
          TOOL,
          { ...INPUT, approval_summary: 'Different' },
          'owner',
          'call-1',
          KEY,
        ),
      ).toThrow();
    });
  });

  it('refuses a model-supplied receipt or arbitrary extra parameters', async () => {
    await withVendosApproval(ACTION, APPROVE, 'owner', async () => {
      expect(() =>
        attestVendosExecution(
          TOOL,
          { ...INPUT, approval_receipt: 'forged' },
          'owner',
          'call-1',
          KEY,
        ),
      ).toThrow();
      expect(() =>
        attestVendosExecution(
          TOOL,
          { ...INPUT, destination: 'another account' },
          'owner',
          'call-1',
          KEY,
        ),
      ).toThrow();
    });
  });

  it('isolates concurrent resumed owners', async () => {
    await Promise.all(
      ['alice', 'bob'].map((user) =>
        withVendosApproval(ACTION, APPROVE, user, async () => {
          await new Promise((resolve) => setTimeout(resolve, 5));
          const result = attestVendosExecution(
            TOOL,
            JSON.stringify(INPUT),
            user,
            'call-1',
            KEY,
          ) as { approval_receipt: string };
          expect(
            JSON.parse(Buffer.from(result.approval_receipt.split('.')[0], 'base64url').toString())
              .actor,
          ).toBe(`librechat-${user}`);
        }),
      ),
    );
  });
});
