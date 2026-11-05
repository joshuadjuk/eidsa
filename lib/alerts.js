/**
 * Webhook alerting after each analysis run.
 *
 * Formats:
 *   teams   — Teams "Workflows" webhook (Adaptive Card message)
 *   slack   — Slack incoming webhook ({ text })
 *   generic — raw JSON payload for SOAR / custom receivers
 *
 * Only detections not alerted before are sent (dedup keys kept in workspace meta).
 */

const SEV_RANK = { low: 1, medium: 2, high: 3, critical: 4 };
const MAX_REMEMBERED = 5000;

function alertKey(d) {
  const who = d.user || d.ip || (d.affectedUsers || [])[0] || '';
  return `${d.type}|${who}|${d.windowStart || d.time || d.firstSeen || ''}`;
}

function selectNewAlerts(detections, { minSeverity = 'high', alertedKeys = [] }) {
  const seen = new Set(alertedKeys);
  const min = SEV_RANK[minSeverity] || 3;
  return detections.filter(d => (SEV_RANK[d.severity] || 0) >= min && !seen.has(alertKey(d)));
}

function buildPayload(format, { workspaceName, detections, criticalUsers, appUrl }) {
  const title = `EIDSA · ${workspaceName}: ${detections.length} new alert${detections.length > 1 ? 's' : ''}`;
  const lines = detections.slice(0, 15).map(d => `[${d.severity.toUpperCase()}] ${d.message}`);
  if (detections.length > 15) lines.push(`…and ${detections.length - 15} more`);
  const crit = criticalUsers.length ? `CRITICAL users: ${criticalUsers.slice(0, 10).join(', ')}` : '';

  if (format === 'slack') {
    return { text: [`*${title}*`, crit, ...lines.map(l => `• ${l}`), appUrl].filter(Boolean).join('\n') };
  }
  if (format === 'teams') {
    return {
      type: 'message',
      attachments: [{
        contentType: 'application/vnd.microsoft.card.adaptive',
        content: {
          $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
          type: 'AdaptiveCard',
          version: '1.4',
          body: [
            { type: 'TextBlock', text: title, weight: 'Bolder', size: 'Medium', wrap: true },
            ...(crit ? [{ type: 'TextBlock', text: crit, color: 'Attention', wrap: true }] : []),
            ...lines.map(l => ({ type: 'TextBlock', text: l, wrap: true, spacing: 'Small' })),
          ],
          ...(appUrl ? { actions: [{ type: 'Action.OpenUrl', title: 'Open EIDSA', url: appUrl }] } : {}),
        },
      }],
    };
  }
  return { source: 'EIDSA', workspace: workspaceName, criticalUsers, detections };
}

async function send(url, payload) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) throw new Error(`Webhook responded ${res.status}`);
}

/**
 * @returns keys of the alerts that were sent (to merge into meta.alertedKeys)
 */
async function dispatch({ url, format = 'generic', minSeverity = 'high', alertedKeys = [], workspaceName, detections, userSummaries = [], appUrl }) {
  const fresh = selectNewAlerts(detections, { minSeverity, alertedKeys });
  if (fresh.length === 0) return [];
  const criticalUsers = userSummaries.filter(s => s.riskLevel === 'CRITICAL').map(s => s.user);
  await send(url, buildPayload(format, { workspaceName, detections: fresh, criticalUsers, appUrl }));
  return fresh.map(alertKey);
}

function mergeKeys(existing = [], added = []) {
  return [...existing, ...added].slice(-MAX_REMEMBERED);
}

module.exports = { dispatch, send, buildPayload, selectNewAlerts, alertKey, mergeKeys };
