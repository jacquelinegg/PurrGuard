# SETUP — от нула до работещ демо проект

Крайният срок на хакатона е **27 октомври 2026, 13:00 UTC**. Път: **Path A (Start Fresh)**, ниво: **Hands-off**.

## 0. Предварително
- Регистрация в Devpost за хакатона + GitLab contributor onboarding (https://contributors.gitlab.com/transcend-hackathon, одобрението отнема ~24 ч).
- В твоя GitLab проект да е включена Duo Agent Platform (AI > Flows трябва да се вижда в страничната лента).
- Локално: Python 3.12, git. За Google Cloud: `gcloud` (или Cloud Shell) и включено таксуване на проекта.

## 1. Локална проверка (5 мин)
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python tests/test_purrguard.py && python tests/test_stegoops.py && python tests/test_autopilot.py
python -m stegoops init-demo
```
`init-demo` прави лого, запечатва 2 **ФАЛШИВИ** тайни и **печата `STEGOOPS_KEK` само веднъж** — копирай го (ще го сложиш в GitLab). Не го комитвай.
Резултатът са променен `app/assets/logo.png` и `.stegoops/manifest.json`: **комитни и двата**.

## 2. GitLab проект
1. Нов **публичен** празен проект. (MIT лицензът е в `LICENSE`; провери, че се вижда в About.)
2. CODEOWNERS: смени `@security-owners` с твоя потребител или група, която съществува.
3. **Преди първия push** настрой по-долу променливите, иначе `deploy-staging` ще падне.

### Настройки
| Къде | Какво |
|---|---|
| Settings > Repository > Protected branches | `main` е protected. **Allowed to merge: Developers + Maintainers** (за да слива ботът). Остави изключено „Require approval from Code Owners“ — иначе auto-merge чака човек. Компенсиращи защити: `rotation-guard`, PurrGuard, „Pipelines must succeed“ |
| Settings > Merge requests | включи **Pipelines must succeed** |
| Settings > Access tokens | токен `purrguard-bot`, роля **Developer**, scope **api**. Копирай стойността |
| Settings > CI/CD > Variables | `STEGOOPS_KEK` = ключът от стъпка 1 — **Masked + Protected, Environment scope: `staging`** |
| | `GITLAB_API_TOKEN` = токенът — **Masked + Protected**, scope: All |
| Deploy > Container Registry | включен (по подразбиране) |

### Първи push
```bash
git init -b main && git add -A && git commit -m "PurrGuard + Stego-Ops"
git remote add origin https://gitlab.com/<потребител>/purrguard-stegoops.git
git push -u origin main
```
Очаквано: `tests`, `stegoops-verify` → `build-app` → `deploy-staging` (в лога: `canary (трябва да е ***): ***`; артефакт `leak_audit.json`, verdict `clean`).
Ако registry клиентът не успее, `--fallback-local` печата предупреждение и продължава с пинатия локален носител — деплоят пак минава.

## 3. Google Cloud (бонус до +0.2 точки)
В Cloud Shell или локално, след `gcloud auth login`:
```bash
export GCP_PROJECT_ID=<твоят-проект>   # по желание: export GCP_REGION=europe-west1
bash deploy/gcp_setup.sh
```
Скриптът включва API-тата, създава Artifact Registry репо `purrguard`, service account `purrguard-ci` с нужните роли и ключ `purrguard-ci-key.json`.
После в GitLab (Settings > CI/CD > Variables):
- `GCP_PROJECT_ID`, `GCP_REGION` (обикновени);
- `GCP_SA_KEY` — тип **File**, съдържание: целият JSON, **Protected**.
Изтрий локалния ключ (`shred -u purrguard-ci-key.json`). Следващият push на `main` пуска `deploy-cloudrun`; публичният адрес е в лога и в артефакта `cloudrun_url.txt` — него слагаш в Devpost.
Ако `--allow-unauthenticated` е блокирано от организационна политика, трябва да се разреши публичен достъп (журито има нужда от публичен линк).
По-добра практика за продукция: Workload Identity Federation вместо ключ (оставено като следваща стъпка).

## 4. Duo flows
1. AI > Flows > New flow → постави `duo/flows/stegoops-mr-guardian.yaml`; triggers: **mention** (и по желание assign/reviewer на flow-а).
2. New flow → постави `duo/flows/stegoops-deploy-sentinel.yaml`; triggers: **Pipeline** (да се задейства при pipeline събития) и **mention**.
3. Flow builder-ът валидира YAML-а. **Тук се очакват дребни корекции**: имената на tools в `toolset` (`create_issue`, `create_issue_note`, `gitlab_api_get`, `get_merge_request`, …) и допустимите полета зависят от версията. Оправи каквото се оплаче и върни поправката в репото.
4. Service account-ът на flow-а трябва да е член на проекта (Developer), за да коментира.
5. MCP: `.gitlab/duo/mcp.json` регистрира `purrguard` MCP сървъра. Провери в твоята версия къде се прилага (напр. Duo Chat в IDE). Споменавай го в подаването само ако го покажеш на видеото.

## 5. График (за автоматичния цикъл)
Build > Pipeline schedules > New schedule: всеки ден, целеви клон `main`. Тя пуска `expiry-watch`, `rotate-secrets`, `purrguard-history` и `pages`.

## 6. Демо на цикъла (сега, без да чакаш 30 дни)
```bash
export STEGOOPS_KEK=<ключът>
python -m stegoops rotate --carrier app/assets/logo.png --ttl-days 3   # скъсява срока до 3 дни
git add -A && git commit -m "demo: кратък срок" && git push
```
Изчакай push pipeline-а, после Build > Pipelines > **Run pipeline** на `main`. Наблюдавай:
1. `expiry-watch` отваря issue с етикет `stegoops::rotation`;
2. `rotate-secrets` отваря MR `stegoops/rotate-…` с auto-merge;
3. pipeline-ът на MR (`rotation-guard`, `purrguard-mr`, `stegoops-verify`, `tests`) минава и MR се слива сам;
4. `build-app` → `deploy-staging` → `deploy-cloudrun`;
5. Deploy Sentinel публикува резултата в issue-то.

Тестът за подменен носител: нов клон с друг `logo.png` → MR → `purrguard-mr` пада (`carrier_tampered`). Остави този MR отворен — нужна е видима pipeline история.

## 7. Подаване
- Попълни в `DEVPOST.md`: линк към репото, YouTube видео (< 3 мин, без чужди марки и музика), линк към Cloud Run.
- Избери **Path A** и ниво **Hands-off**; при желание — Google Cloud бонус (линкът трябва да е публичен до обявяване на победителите).
- Сигурност на репото: ако се съмняваш, че KEK е изтекъл, ротирай го (`keygen`, нов `seal`) преди да направиш проекта публичен.
