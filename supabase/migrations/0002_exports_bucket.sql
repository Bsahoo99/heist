-- The exported replays (`pnpm export` in web/): <id>.mp4, <id>.gif and <id>.png.
-- A private bucket with no storage policies: only the service role reaches it (the export
-- script uploads, the engine signs short-lived links). A public bucket would be Heist's own
-- mistake 4. Safe to run twice.

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('exports', 'exports', false, 52428800, array['video/mp4', 'image/gif', 'image/png'])
on conflict (id) do nothing;
