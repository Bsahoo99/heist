-- HEIST-FIXTURE: m4 (pet-photos, low, public by design)
insert into storage.buckets (id, name, public) values ('pet-photos', 'pet-photos', true);

-- HEIST-FIXTURE: m4 (id-documents, low, private bucket with no policies on storage.objects)
insert into storage.buckets (id, name, public) values ('id-documents', 'id-documents', false);
