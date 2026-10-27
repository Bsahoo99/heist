import { useEffect, useState } from 'react'
import { supabase } from '../lib/supabase'

export default function Pets() {
  const [pets, setPets] = useState<any[]>([])

  useEffect(() => {
    supabase
      .from('pets')
      .select()
      .then(({ data }) => setPets(data ?? []))
  }, [])

  return (
    <ul>
      {pets.map((p) => (
        <li key={p.id}>{p.name} ({p.species})</li>
      ))}
    </ul>
  )
}
