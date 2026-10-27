import { supabase } from '../lib/supabase'

export default function Upload() {
  async function onChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    const { data: { user } } = await supabase.auth.getUser()
    await supabase.storage
      .from('id-documents')
      .upload(`${user?.id}/${file.name}`, file)
  }

  return <input type="file" onChange={onChange} />
}
