DO $$
BEGIN

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'field_choice_type') THEN
    CREATE TYPE field_choice_type AS ENUM (
      'Text',
      'Number',
      'DateTime'
    );
  END IF;

  CREATE TABLE IF NOT EXISTS field_choices (
    id UUID DEFAULT uuidv7() PRIMARY KEY,
    field_id UUID NOT NULL REFERENCES fields(id) ON DELETE CASCADE,
    description TEXT,
    type field_choice_type NOT NULL,
    text_value TEXT,
    number_value DECIMAL,
    date_time_value TIMESTAMPTZ
  );

END
$$ LANGUAGE plpgsql;
