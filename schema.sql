-- =====================================================================
--  Class Library — database setup
--  Paste this whole file into Supabase → SQL Editor → New query → Run.
--  Safe to run once on a fresh project.
-- =====================================================================

-- ---------- Profiles (one per account) ----------
create table public.profiles (
  id           uuid primary key references auth.users(id) on delete cascade,
  display_name text not null check (char_length(display_name) between 1 and 60),
  role         text not null default 'student' check (role in ('student', 'teacher')),
  approved     boolean not null default false,
  created_at   timestamptz not null default now()
);

-- Create a profile automatically whenever someone signs up
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, display_name)
  values (
    new.id,
    left(coalesce(
      nullif(trim(new.raw_user_meta_data->>'display_name'), ''),
      nullif(trim(new.raw_user_meta_data->>'full_name'), ''),
      split_part(new.email, '@', 1)
    ), 60)
  );
  return new;
end $$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Helper checks used by the security rules below
create or replace function public.is_approved()
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((select approved from public.profiles where id = auth.uid()), false)
$$;

create or replace function public.is_teacher()
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((select approved and role = 'teacher' from public.profiles where id = auth.uid()), false)
$$;

alter table public.profiles enable row level security;

-- You can always see yourself; approved members can see the class list
create policy "profiles: read" on public.profiles
  for select using (id = auth.uid() or public.is_approved());

-- People may change only their own display name (not role/approval)
revoke update on public.profiles from authenticated, anon;
grant update (display_name) on public.profiles to authenticated;
create policy "profiles: edit own name" on public.profiles
  for update using (id = auth.uid()) with check (id = auth.uid());

-- Teacher approves / revokes accounts through this function
create or replace function public.set_approved(target uuid, value boolean)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.is_teacher() then
    raise exception 'Only a teacher can do that';
  end if;
  if target = auth.uid() then
    raise exception 'You cannot change your own access';
  end if;
  update public.profiles set approved = value where id = target;
end $$;

revoke execute on function public.set_approved(uuid, boolean) from anon;

-- ---------- Works (essays, poems, stories...) ----------
create table public.works (
  id         uuid primary key default gen_random_uuid(),
  author_id  uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  title      text not null check (char_length(title) between 1 and 200),
  kind       text not null default 'Essay'
             check (kind in ('Essay', 'Poem', 'Short Story', 'Book Report', 'Journal', 'Other')),
  body       text check (char_length(body) <= 100000),
  file_path  text,
  file_name  text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint has_content check (coalesce(char_length(body), 0) > 0 or file_path is not null)
);

create index works_created_idx on public.works (created_at desc);

alter table public.works enable row level security;

create policy "works: approved members read" on public.works
  for select using (public.is_approved());

create policy "works: approved members post their own" on public.works
  for insert with check (public.is_approved() and author_id = auth.uid());

create policy "works: authors edit their own" on public.works
  for update using (public.is_approved() and author_id = auth.uid())
  with check (author_id = auth.uid());

create policy "works: authors or teacher delete" on public.works
  for delete using ((public.is_approved() and author_id = auth.uid()) or public.is_teacher());

-- ---------- File storage (private bucket) ----------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'works', 'works', false, 10485760,   -- 10 MB per file
  array[
    'application/pdf',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/msword',
    'text/plain',
    'image/png', 'image/jpeg', 'image/gif', 'image/webp'
  ]
);

create policy "files: approved members read" on storage.objects
  for select using (bucket_id = 'works' and public.is_approved());

-- Files go in a folder named after the uploader's id
create policy "files: upload into own folder" on storage.objects
  for insert with check (
    bucket_id = 'works' and public.is_approved()
    and (storage.foldername(name))[1] = auth.uid()::text
  );

create policy "files: delete own, or teacher" on storage.objects
  for delete using (
    bucket_id = 'works'
    and ((storage.foldername(name))[1] = auth.uid()::text or public.is_teacher())
  );

-- ---------- Class chat: spaces, direct messages, essays in chat ----------

-- One row of chat settings the teacher controls
create table public.chat_settings (
  id          int primary key default 1 check (id = 1),
  dms_enabled boolean not null default true
);
insert into public.chat_settings default values;
alter table public.chat_settings enable row level security;
create policy "settings: members read" on public.chat_settings
  for select using (public.is_approved());

create or replace function public.set_dms_enabled(value boolean)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.is_teacher() then raise exception 'Only a teacher can do that'; end if;
  update public.chat_settings set dms_enabled = value where id = 1;
end $$;

-- Rooms: "space" = open to the whole class, "dm" = two people, "group" = private chat with chosen people
create table public.rooms (
  id              uuid primary key default gen_random_uuid(),
  kind            text not null check (kind in ('space', 'dm', 'group')),
  name            text check (name is null or char_length(name) between 1 and 60),
  dm_key          text unique,
  created_by      uuid references public.profiles(id) on delete set null,
  created_at      timestamptz not null default now(),
  last_message_at timestamptz,
  check ((kind = 'space' and name is not null) or (kind = 'dm' and dm_key is not null) or kind = 'group')
);

create table public.room_members (
  room_id uuid not null references public.rooms(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  primary key (room_id, user_id)
);

-- Who can see a room: any approved member for spaces; for private chats (DMs and groups), the members and the teacher
create or replace function public.can_see_room(r uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select public.is_approved() and exists (
    select 1 from public.rooms ro
    where ro.id = r and (
      ro.kind = 'space' or public.is_teacher()
      or exists (select 1 from public.room_members m where m.room_id = r and m.user_id = auth.uid())
    ))
$$;

-- Who can post: any approved member in spaces; in private chats only members, and only while private chats are on
create or replace function public.can_post_room(r uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select public.is_approved() and exists (
    select 1 from public.rooms ro
    where ro.id = r and (
      ro.kind = 'space'
      or ((select dms_enabled from public.chat_settings where id = 1)
          and exists (select 1 from public.room_members m where m.room_id = r and m.user_id = auth.uid()))
    ))
$$;

alter table public.rooms enable row level security;
alter table public.room_members enable row level security;

create policy "rooms: visible rooms" on public.rooms
  for select using (public.can_see_room(id));
create policy "rooms: teacher deletes spaces" on public.rooms
  for delete using (public.is_teacher() and kind = 'space' and created_by is not null);
create policy "room members: visible rooms" on public.room_members
  for select using (public.can_see_room(room_id));

-- Start a new space (any approved member)
create or replace function public.create_space(space_name text)
returns uuid language plpgsql security definer set search_path = public as $$
declare rid uuid;
begin
  if not public.is_approved() then raise exception 'Your account is not approved yet'; end if;
  if char_length(trim(coalesce(space_name, ''))) = 0 then raise exception 'Give the space a name'; end if;
  insert into public.rooms (kind, name, created_by)
  values ('space', left(trim(space_name), 40), auth.uid())
  returning id into rid;
  return rid;
end $$;

-- Open (or reuse) a direct-message room with one classmate
create or replace function public.open_dm(other uuid)
returns uuid language plpgsql security definer set search_path = public as $$
declare rid uuid; k text;
begin
  if not public.is_approved() then raise exception 'Your account is not approved yet'; end if;
  if other = auth.uid() then raise exception 'You cannot message yourself'; end if;
  if not exists (select 1 from public.profiles where id = other and approved) then
    raise exception 'That person is not in the class';
  end if;
  k := least(auth.uid()::text, other::text) || ':' || greatest(auth.uid()::text, other::text);
  select id into rid from public.rooms where dm_key = k;
  if rid is null then
    if not (select dms_enabled from public.chat_settings where id = 1) then
      raise exception 'Private chats are turned off by the teacher';
    end if;
    insert into public.rooms (kind, dm_key, created_by) values ('dm', k, auth.uid()) returning id into rid;
    insert into public.room_members (room_id, user_id) values (rid, auth.uid()), (rid, other);
  end if;
  return rid;
end $$;

-- Private group chats -------------------------------------------------
create or replace function public.private_chats_on()
returns boolean language sql stable security definer set search_path = public as $$
  select dms_enabled from public.chat_settings where id = 1
$$;

create or replace function public.check_classmates(ids uuid[])
returns void language plpgsql stable security definer set search_path = public as $$
begin
  if exists (select 1 from unnest(ids) u(id)
             where not exists (select 1 from public.profiles p where p.id = u.id and p.approved)) then
    raise exception 'Everyone you add must be in the class';
  end if;
end $$;

-- Start a group chat with chosen classmates (you're added automatically)
create or replace function public.create_group(member_ids uuid[], group_name text default null)
returns uuid language plpgsql security definer set search_path = public as $$
declare rid uuid; others uuid[];
begin
  if not public.is_approved() then raise exception 'Your account is not approved yet'; end if;
  if not public.private_chats_on() then raise exception 'Private chats are turned off by the teacher'; end if;
  select coalesce(array_agg(distinct x), '{}') into others from unnest(member_ids) x where x <> auth.uid();
  if cardinality(others) < 2 then raise exception 'Pick at least two classmates for a group chat'; end if;
  if cardinality(others) > 49 then raise exception 'Group chats can have up to 50 people'; end if;
  perform public.check_classmates(others);
  insert into public.rooms (kind, name, created_by)
  values ('group', nullif(left(trim(coalesce(group_name, '')), 60), ''), auth.uid())
  returning id into rid;
  insert into public.room_members (room_id, user_id)
  select rid, x from unnest(others || auth.uid()) x;
  return rid;
end $$;

-- Add people to a group chat you're in
create or replace function public.add_group_members(r uuid, member_ids uuid[])
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.is_approved() then raise exception 'Your account is not approved yet'; end if;
  if not public.private_chats_on() then raise exception 'Private chats are turned off by the teacher'; end if;
  if not exists (select 1 from public.rooms ro join public.room_members m on m.room_id = ro.id
                 where ro.id = r and ro.kind = 'group' and m.user_id = auth.uid()) then
    raise exception 'You can only add people to a group chat you are in';
  end if;
  perform public.check_classmates(member_ids);
  insert into public.room_members (room_id, user_id)
  select r, x from unnest(member_ids) x on conflict do nothing;
  if (select count(*) from public.room_members where room_id = r) > 50 then
    raise exception 'Group chats can have up to 50 people';
  end if;
end $$;

-- Rename a group chat you're in (empty name = show member names)
create or replace function public.rename_group(r uuid, new_name text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.rooms ro join public.room_members m on m.room_id = ro.id
                 where ro.id = r and ro.kind = 'group' and m.user_id = auth.uid()) or not public.is_approved() then
    raise exception 'You can only rename a group chat you are in';
  end if;
  update public.rooms set name = nullif(left(trim(coalesce(new_name, '')), 60), '') where id = r;
end $$;

-- Leave a group chat (the chat is removed when the last person leaves)
create or replace function public.leave_group(r uuid)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.rooms where id = r and kind = 'group') then
    raise exception 'You can only leave group chats';
  end if;
  delete from public.room_members where room_id = r and user_id = auth.uid();
  if not exists (select 1 from public.room_members where room_id = r) then
    delete from public.rooms where id = r;
  end if;
end $$;

revoke execute on function public.create_group(uuid[], text) from anon;
revoke execute on function public.add_group_members(uuid, uuid[]) from anon;
revoke execute on function public.rename_group(uuid, text) from anon;
revoke execute on function public.leave_group(uuid) from anon;
revoke execute on function public.create_space(text) from anon;
revoke execute on function public.open_dm(uuid) from anon;
revoke execute on function public.set_dms_enabled(boolean) from anon;

-- Messages (text, a shared essay, or both)
create table public.messages (
  id         bigint generated always as identity primary key,
  room_id    uuid not null references public.rooms(id) on delete cascade,
  author_id  uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  body       text check (body is null or char_length(body) <= 1000),
  work_id    uuid references public.works(id) on delete set null,
  created_at timestamptz not null default now()
);
create index messages_room_idx on public.messages (room_id, created_at desc);

alter table public.messages enable row level security;
create policy "messages: read in visible rooms" on public.messages
  for select using (public.can_see_room(room_id));
create policy "messages: post as yourself" on public.messages
  for insert with check (author_id = auth.uid() and public.can_post_room(room_id));
create policy "messages: delete own, or teacher" on public.messages
  for delete using ((author_id = auth.uid() and public.is_approved()) or public.is_teacher());

-- Anti-spam and empty-message check
create or replace function public.messages_before_insert()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if char_length(trim(coalesce(new.body, ''))) = 0 and new.work_id is null then
    raise exception 'Message is empty';
  end if;
  if (select count(*) from public.messages
      where author_id = new.author_id and created_at > now() - interval '10 seconds') >= 5 then
    raise exception 'Slow down a little: too many messages at once.';
  end if;
  return new;
end $$;
create trigger messages_before_insert before insert on public.messages
  for each row execute function public.messages_before_insert();

-- Keep each room's "last message" time current (for unread markers)
create or replace function public.messages_after_insert()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  update public.rooms set last_message_at = new.created_at where id = new.room_id;
  return new;
end $$;
create trigger messages_after_insert after insert on public.messages
  for each row execute function public.messages_after_insert();

-- What each person has read (private to them)
create table public.room_reads (
  user_id      uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  room_id      uuid not null references public.rooms(id) on delete cascade,
  last_read_at timestamptz not null,
  primary key (user_id, room_id)
);
alter table public.room_reads enable row level security;
create policy "reads: your own" on public.room_reads
  for all using (user_id = auth.uid()) with check (user_id = auth.uid());

-- The default space everyone starts in
insert into public.rooms (kind, name) values ('space', 'General');

-- Live updates
alter publication supabase_realtime add table public.messages, public.rooms, public.room_members;

-- =====================================================================
--  AFTER you create your own account on the site, make yourself the
--  teacher/admin by running this (with your email):
--
--  update public.profiles set role = 'teacher', approved = true
--  where id = (select id from auth.users where email = 'you@example.com');
-- =====================================================================
