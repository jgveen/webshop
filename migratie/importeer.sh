#!/bin/bash
BESTAND="/root/webshop/migratie/export_nas.sql"

if [ ! -f "$BESTAND" ]; then
  echo "FOUT: $BESTAND niet gevonden. Upload het bestand eerst."
  exit 1
fi

echo "=== Huidige aantallen VOOR import ==="
mysql -u root webshop -e "
  SELECT 'producten' AS tabel, COUNT(*) AS aantal FROM producten WHERE verwijderd_op IS NULL
  UNION SELECT 'productgroepen', COUNT(*) FROM productgroepen WHERE verwijderd_op IS NULL
  UNION SELECT 'gebruikers', COUNT(*) FROM gebruikers WHERE verwijderd_op IS NULL;"

echo ""
echo "=== Importeren... ==="
mysql -u root webshop < "$BESTAND"

if [ $? -eq 0 ]; then
  echo "Import geslaagd!"
else
  echo "FOUT bij importeren. Controleer het bestand."
  exit 1
fi

echo ""
echo "=== Aantallen NA import ==="
mysql -u root webshop -e "
  SELECT 'producten' AS tabel, COUNT(*) AS aantal FROM producten WHERE verwijderd_op IS NULL
  UNION SELECT 'productgroepen', COUNT(*) FROM productgroepen WHERE verwijderd_op IS NULL
  UNION SELECT 'gebruikers', COUNT(*) FROM gebruikers WHERE verwijderd_op IS NULL;"
