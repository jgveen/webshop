-- ============================================================
-- MAPPING SCRIPT — Scenario C: andere tabelstructuur
-- Pas de kolomnamen aan naar jouw NAS-database structuur
-- ============================================================

-- STAP 1: Maak een tijdelijke tabel met jouw NAS-structuur
-- (pas de kolommen aan zodat ze overeenkomen met jouw NAS-DB)

-- Voorbeeld: als jouw NAS producten-tabel andere namen heeft
-- zoals "title" i.p.v. "naam" en "price" i.p.v. "prijs"

-- Zet hier jouw export neer en gebruik INSERT ... SELECT om te mappen:

-- PRODUCTGROEPEN
-- INSERT INTO productgroepen (naam, beschrijving)
-- SELECT jouw_naam_kolom, jouw_beschrijving_kolom
-- FROM jouw_nas_tabel_naam;

-- PRODUCTEN (doe groepen EERST zodat groep_id klopt)
-- INSERT INTO producten (naam, beschrijving, prijs, groep_id)
-- SELECT jouw_naam, jouw_beschrijving, jouw_prijs, jouw_groep_id
-- FROM jouw_nas_producten_tabel;

-- GEBRUIKERS/KLANTEN
-- Wachtwoorden MOETEN bcrypt hashes zijn ($2b$10$...)
-- Als ze plain-text zijn of MD5, kunnen ze niet direct geïmporteerd worden.
-- INSERT INTO gebruikers (voornaam, achternaam, email, wachtwoord, rol)
-- SELECT voornaam, achternaam, email, wachtwoord, 'klant'
-- FROM jouw_nas_klanten_tabel
-- WHERE wachtwoord LIKE '$2%';  -- alleen bcrypt hashes

-- ============================================================
-- LET OP bij gebruikers:
-- - Email moet uniek zijn
-- - Wachtwoord MOET een bcrypt hash zijn ($2b$10$...)
-- - Rol moet 'admin', 'medewerker' of 'klant' zijn
-- ============================================================
