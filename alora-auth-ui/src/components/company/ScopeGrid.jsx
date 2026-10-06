import { FEATURES, LEVELS, LEVEL_LABELS, changed, levelOf, scopesAt, withLevel } from '../../utils/scopes'
import { Badge } from '../ui/Layout'

const TONES = { read: 'blue', edit: 'brand' }

export function LevelBadge({ level }) {
  if (level === 'none') return <span className="text-gray-300">—</span>
  return <Badge tone={TONES[level]}>{LEVEL_LABELS[level]}</Badge>
}

// The App Central access table: one row per feature, None / Read / Edit. It
// edits a group's scopes and a person's extras, and shows anyone's access.
//
//   value      the scopes shown (an edit scope comes with its read scope)
//   onChange   makes the grid editable; called with the new list
//   saved      the scopes as stored: rule 1 is about what a change gives or
//              takes away, so an option is judged against these
//   canGive    scopes -> whether the viewer may give or take them away; an
//              option that would change a scope they lack is disabled
//   inherited  what the person already has from their groups, in a column of
//              its own
//   sources    feature key -> where the access comes from, in a column of its own
export default function ScopeGrid({ value, onChange, saved = value, canGive = () => true, inherited, sources, name = 'scope' }) {
  const editable = !!onChange
  return (
    <div className="overflow-x-auto">
      <table className="min-w-full text-sm" data-testid="scope-grid">
        <thead>
          <tr className="text-left text-xs font-medium uppercase tracking-wide text-gray-400">
            <th className="py-2 pr-4 font-medium">Feature</th>
            {inherited && <th className="py-2 pr-4 font-medium">From groups</th>}
            {editable
              ? LEVELS.map(l => <th key={l} className="px-3 py-2 text-center font-medium">{inherited ? `Extra: ${LEVEL_LABELS[l]}` : LEVEL_LABELS[l]}</th>)
              : <th className="py-2 pr-4 font-medium">{inherited ? 'Extra' : 'Access'}</th>}
            {sources && <th className="py-2 pr-4 font-medium">From</th>}
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100">
          {FEATURES.map(f => {
            const level = levelOf(value, f)
            return (
              <tr key={f.key} data-testid={`scope-row-${f.key}`} data-level={level}>
                <td className="py-2 pr-4">
                  <div className="font-medium text-gray-900">{f.label}</div>
                  <div className="text-xs text-gray-400">
                    Read: {f.lets}{f.edit && <><br />Edit: {f.editLets}</>}
                  </div>
                </td>
                {inherited && <td className="py-2 pr-4"><LevelBadge level={levelOf(inherited, f)} /></td>}
                {editable ? LEVELS.map(l => {
                  if (l === 'edit' && !f.edit) return <td key={l} className="px-3 py-2 text-center text-gray-300">—</td>
                  const allowed = canGive(changed(scopesAt(f, levelOf(saved, f)), scopesAt(f, l)))
                  return (
                    <td key={l} className="px-3 py-2 text-center">
                      <input
                        type="radio" name={`${name}-${f.key}`} aria-label={`${f.label}: ${LEVEL_LABELS[l]}`}
                        className="h-4 w-4 border-gray-300 text-brand-500 focus:ring-brand-500 disabled:opacity-40"
                        checked={level === l} disabled={!allowed}
                        title={allowed ? undefined : 'You can only give or take away access you hold yourself'}
                        onChange={() => onChange(withLevel(value, f, l))}
                      />
                    </td>
                  )
                }) : <td className="py-2 pr-4"><LevelBadge level={level} /></td>}
                {sources && <td className="py-2 pr-4 text-gray-500">{sources[f.key] ?? '—'}</td>}
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
