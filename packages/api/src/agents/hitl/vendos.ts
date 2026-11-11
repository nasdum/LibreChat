import { createHmac } from 'crypto';
import { AsyncLocalStorage } from 'async_hooks';
import type { HookCallback } from '@librechat/agents';
import type { Agents } from 'librechat-data-provider';

const EXECUTOR = 'execute_approved_change_mcp_vendos_pilot';

export const vendosApprovalHook: HookCallback<'PreToolUse'> = async (input) => {
  if (input.toolName !== EXECUTOR) {
    return {};
  }
  return {
    decision: 'ask',
    reason:
      'VENDOS: schvalujete přesnou změnu uvedenou v approval_summary. Bez tohoto souhlasu se neprovede. Úprava návrhu vyžaduje nový plán.',
    allowedDecisions: ['approve', 'reject'],
  };
};

interface ExecutionArguments {
  project: string;
  plan_id: string;
  plan_hash: string;
  approval_summary: string;
  approval_receipt?: string;
}

interface ApprovalContext {
  userId: string;
  actionId: string;
  calls: Map<string, ExecutionArguments>;
}

const approvalContext = new AsyncLocalStorage<ApprovalContext>();

function executionArguments(input: string | object): ExecutionArguments {
  const value: Partial<ExecutionArguments> = typeof input === 'string' ? JSON.parse(input) : input;
  const fields = ['project', 'plan_id', 'plan_hash', 'approval_summary'] as const;
  if (
    value == null ||
    Array.isArray(value) ||
    Object.keys(value).some((key) => ![...fields, 'approval_receipt'].includes(key)) ||
    fields.some((key) => typeof value[key] !== 'string' || !value[key]) ||
    value.project !== 'vendos-cz' ||
    !/^act-[a-f0-9]{20}$/.test(value.plan_id ?? '') ||
    !/^[a-f0-9]{64}$/.test(value.plan_hash ?? '') ||
    (value.approval_summary?.length ?? 0) > 20000 ||
    (value.approval_receipt != null && value.approval_receipt !== '')
  ) {
    throw new Error('Invalid VENDOS execution offer; prepare and review a fresh plan');
  }
  return {
    project: value.project,
    plan_id: value.plan_id,
    plan_hash: value.plan_hash,
    approval_summary: value.approval_summary,
  } as ExecutionArguments;
}

/** Call only after the authenticated native resume route wins its approval CAS. */
export function withVendosApproval<T>(
  pending: Agents.PendingAction,
  decisions: Agents.ToolApprovalResolution[] | undefined,
  userId: string,
  run: () => Promise<T>,
): Promise<T> {
  const calls = new Map<string, ExecutionArguments>();
  if (pending.payload?.type === 'tool_approval') {
    const approved = new Set(
      (decisions ?? [])
        .filter((value) => value.decision === 'approve')
        .map((value) => value.tool_call_id),
    );
    for (const call of pending.payload.action_requests) {
      if (call.name === EXECUTOR && approved.has(call.tool_call_id)) {
        calls.set(call.tool_call_id, executionArguments(call.arguments));
      }
    }
  }
  return approvalContext.run({ userId, actionId: pending.actionId, calls }, run);
}

/** The private per-user MCP key is never included in model input or a tool schema. */
export function attestVendosExecution(
  toolName: string,
  input: string | object,
  userId: string,
  toolCallId: string | undefined,
  bearerKey: string | undefined,
): string | object {
  if (toolName !== EXECUTOR) {
    return input;
  }
  const context = approvalContext.getStore();
  const args = executionArguments(input);
  const approved = toolCallId ? context?.calls.get(toolCallId) : undefined;
  if (
    !context ||
    context.userId !== userId ||
    !toolCallId ||
    !approved ||
    JSON.stringify(approved) !== JSON.stringify(args) ||
    !bearerKey ||
    bearerKey.length < 24
  ) {
    throw new Error(
      'VENDOS requires the owner to click Approve on this exact proposal in LibreChat',
    );
  }
  context.calls.delete(toolCallId);
  const body = Buffer.from(
    JSON.stringify({
      v: 1,
      actor: `librechat-${userId}`,
      tool: EXECUTOR,
      arguments: args,
      nonce: `${context.actionId}:${toolCallId}`,
      issued_at: Date.now(),
    }),
  ).toString('base64url');
  const signature = createHmac('sha256', bearerKey).update(body).digest('hex');
  return { ...args, approval_receipt: `${body}.${signature}` };
}
