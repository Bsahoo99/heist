insert into storage.buckets (id, name, public) values ('pet-photos', 'pet-photos', true);

insert into storage.buckets (id, name, public) values ('id-documents', 'id-documents', false);

create policy "pet_photos_read" on storage.objects for select using (bucket_id = 'pet-photos');

create policy "id_documents_select_own" on storage.objects for select using (bucket_id = 'id-documents' and auth.uid()::text = (storage.foldername(name))[1]);

create policy "id_documents_insert_own" on storage.objects for insert with check (bucket_id = 'id-documents' and auth.uid()::text = (storage.foldername(name))[1]);
