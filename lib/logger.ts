type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LogContext {
  [key: string]: unknown;
}

function formatLog(level: LogLevel, message: string, context?: LogContext) {
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    message,
    ...context,
  };

  if (process.env.NODE_ENV === 'development') {
    const prefix = `[${level.toUpperCase()}]`;
    if (level === 'error') console.error(prefix, message, context ?? '');
    else if (level === 'warn') console.warn(prefix, message, context ?? '');
    else console.log(prefix, message, context ?? '');
  } else {
    const out = JSON.stringify(entry);
    if (level === 'error') process.stderr.write(out + '\n');
    else process.stdout.write(out + '\n');
  }
}

export const logger = {
  debug: (msg: string, ctx?: LogContext) => formatLog('debug', msg, ctx),
  info: (msg: string, ctx?: LogContext) => formatLog('info', msg, ctx),
  warn: (msg: string, ctx?: LogContext) => formatLog('warn', msg, ctx),
  error: (msg: string, ctx?: LogContext) => formatLog('error', msg, ctx),
};
