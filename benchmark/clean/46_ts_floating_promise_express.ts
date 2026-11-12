import { Request, Response, NextFunction } from 'express';
export async function handleUser(req: Request, res: Response, next: NextFunction) {
  try {
    await auditLog(req.body.id);
    res.json({ ok: true });
  } catch (err) { next(err); }
}
