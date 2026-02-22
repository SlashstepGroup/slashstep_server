DO $$
  BEGIN

    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'configuration_value_parent_resource_type') THEN
      CREATE TYPE configuration_value_parent_resource_type AS ENUM (
        'Configuration',
        'Server'
      );
    END IF;

    CREATE TABLE IF NOT EXISTS configuration_values (
      id UUID PRIMARY KEY DEFAULT uuidv7(),
      configuration_id UUID NOT NULL REFERENCES configurations(id) ON DELETE CASCADE,
      parent_resource_type configuration_value_parent_resource_type NOT NULL,
      parent_configuration_id UUID REFERENCES configurations(id) ON DELETE CASCADE,
      value_type configuration_value_type NOT NULL,
      text_value TEXT,
      number_value DECIMAL,
      boolean_value BOOLEAN,
      CONSTRAINT value_type_match CHECK (
        (value_type = 'Text' AND text_value IS NOT NULL AND number_value IS NULL AND boolean_value IS NULL) OR
        (value_type = 'Number' AND number_value IS NOT NULL AND text_value IS NULL AND boolean_value IS NULL) OR
        (value_type = 'Boolean' AND boolean_value IS NOT NULL AND text_value IS NULL AND number_value IS NULL)
      )
    );

  END
$$ LANGUAGE plpgsql;