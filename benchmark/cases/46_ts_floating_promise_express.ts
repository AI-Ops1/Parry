import { Request, Response } from 'express';
export function handleUser(req: Request, res: Response) {
  auditLog(req.body.id);
  res.json({ ok: true });
}
