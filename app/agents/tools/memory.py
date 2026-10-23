"""Run-scoped scratch memory. Notes persist as AgentStep rows (kind 'tool', name 'note') so they
survive across tool calls, which each get a fresh ToolContext, and remain in the run trace."""
from __future__ import annotations

from sqlalchemy import func, select

from ...core.security import redact
from ...models import AgentRun, AgentStep, dumps, loads
from .registry import ToolContext, registry

NOTE_LIMIT = 2000
MAX_NOTES = 50


def _run_owned(ctx: ToolContext) -> bool:
    run = ctx.db.get(AgentRun, ctx.run_id) if ctx.run_id else None
    return bool(run and run.tenant_id == ctx.principal.tenant_id)


def _note_rows(ctx: ToolContext) -> list[AgentStep]:
    stmt = (select(AgentStep).where(AgentStep.run_id == ctx.run_id, AgentStep.kind == 'tool', AgentStep.name == 'note', AgentStep.error == '')
            .order_by(AgentStep.created_at.asc(), AgentStep.index.asc()))
    return list(ctx.db.execute(stmt).scalars().all())


def notes_for_run(ctx: ToolContext) -> list[str]:
    """Distinct note texts in order. Tolerates both rows written here (output.text) and the
    runtime's own trace row for the note call (input.text)."""
    seen: list[str] = []
    for row in _note_rows(ctx):
        text = loads(row.output_json).get('text') or loads(row.input_json).get('text') or ''
        if text and text not in seen:
            seen.append(text)
    return seen


@registry.tool('note', 'Save a short working note for this run (hypotheses, ids to revisit, intermediate conclusions). Read back with recall.',
               {'properties': {'text': {'type': 'string'}}, 'required': ['text']}, tags=('memory',))
def note(args: dict, ctx: ToolContext) -> dict:
    if not _run_owned(ctx):
        return {'saved': False, 'reason': 'no run context'}
    text = redact(str(args.get('text', '')))[:NOTE_LIMIT].strip()
    if not text:
        return {'saved': False, 'reason': 'empty note'}
    count = ctx.db.scalar(select(func.count()).select_from(AgentStep).where(AgentStep.run_id == ctx.run_id, AgentStep.name == 'note')) or 0
    if count >= MAX_NOTES:
        return {'saved': False, 'reason': f'note limit of {MAX_NOTES} reached'}
    ctx.db.add(AgentStep(run_id=ctx.run_id, index=1000 + count, kind='tool', name='note', input_json=dumps({'text': text}),
                         output_json=dumps({'text': text, 'saved': True})))
    ctx.db.flush()
    return {'saved': True, 'text': text, 'notes': count + 1}


@registry.tool('recall', 'Return every note saved earlier in this run, oldest first.', {'properties': {}, 'required': []}, tags=('memory',))
def recall(args: dict, ctx: ToolContext) -> dict:
    if not _run_owned(ctx):
        return {'notes': [], 'count': 0}
    notes = notes_for_run(ctx)
    return {'notes': notes, 'count': len(notes)}
