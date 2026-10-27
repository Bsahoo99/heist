import { useEffect, useState } from 'react'
import { supabase } from '../lib/supabase'

export default function Requests() {
  const [requests, setRequests] = useState<any[]>([])

  useEffect(() => {
    supabase
      .from('adoption_requests')
      .select()
      .then(({ data }) => setRequests(data ?? []))
  }, [])

  async function approve(id: string) {
    await supabase.functions.invoke('update-request', {
      body: { id, status: 'approved' },
    })
  }

  return (
    <ul>
      {requests.map((r) => (
        <li key={r.id}>
          {r.message}
          <button onClick={() => approve(r.id)}>Approve</button>
        </li>
      ))}
    </ul>
  )
}
