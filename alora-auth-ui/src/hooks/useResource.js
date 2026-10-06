import { useCallback, useEffect, useRef, useState } from 'react'

// Loads something once its inputs are known, and again on reload(). A response
// that arrives after a newer request started is dropped, so a slow earlier
// answer can never overwrite a later one.
export default function useResource(load, deps) {
  const [state, setState] = useState({ data: null, error: null, loading: true })
  const latest = useRef(0)

  // eslint-disable-next-line react-hooks/exhaustive-deps
  const reload = useCallback(async () => {
    const mine = ++latest.current
    setState(s => ({ ...s, loading: true, error: null }))
    try {
      const data = await load()
      if (mine === latest.current) setState({ data, error: null, loading: false })
    } catch (error) {
      if (mine === latest.current) setState(s => ({ data: s.data, error, loading: false }))
    }
  }, deps)

  useEffect(() => { reload() }, [reload])

  const setData = useCallback(update => {
    setState(s => ({ ...s, data: typeof update === 'function' ? update(s.data) : update }))
  }, [])

  return { ...state, reload, setData }
}
