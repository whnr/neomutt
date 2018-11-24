#define TEST_NO_MAIN
#include "acutest.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "mutt/file.h"

static const char *lines[] = {
  "This is the first line.",
  "The second line.",
  "And the third line",
  NULL,
};

#define NUM_TEST_LINES (sizeof(lines) / sizeof(const char *) - 1)

static FILE *set_up(const char *funcname)
{
  int res = 0;
  FILE *fp = tmpfile();
  const char **linep = NULL;
  if (fp == NULL)
    goto err1;
  for (linep = lines; *linep != NULL; linep++)
  {
    res = fputs(*linep, fp);
    if (res == EOF)
      goto err2;
    res = fputc('\n', fp);
    if (res == EOF)
      goto err2;
  }
  rewind(fp);
  return fp;
err2:
  fclose(fp);
err1:
  TEST_MSG("Failed to set up test %s", funcname);
  return NULL;
}

#define SET_UP() (set_up(__FUNCTION__))

static void tear_down(FILE *fp, const char *funcname)
{
  int res = fclose(fp);
  if (res == EOF)
    TEST_MSG("Failed to tear down test %s", funcname);
}

#define TEAR_DOWN(fp) (tear_down((fp), __FUNCTION__))

void test_file_iter_line(void)
{
  FILE *fp = SET_UP();
  if (fp == NULL)
    return;
  struct mutt_file_iter iter = { 0 };
  int i;
  bool res;
  for (i = 0; i < NUM_TEST_LINES; i++)
  {
    res = mutt_file_iter_line(&iter, fp, 0);
    if (!TEST_CHECK(res))
    {
      TEST_MSG("Expected: true");
      TEST_MSG("Actual: false");
    }
    if (!TEST_CHECK(strcmp(iter.line, lines[i]) == 0))
    {
      TEST_MSG("Expected: %s", lines[i]);
      TEST_MSG("Actual: %s", iter.line);
    }
    if (!TEST_CHECK(iter.line_num == i + 1))
    {
      TEST_MSG("Expected: %d", i + 1);
      TEST_MSG("Actual: %d", iter.line_num);
    }
  }
  res = mutt_file_iter_line(&iter, fp, 0);
  if (!TEST_CHECK(!res))
  {
    TEST_MSG("Expected: false");
    TEST_MSG("Actual: true");
  }
  TEAR_DOWN(fp);
}

static bool mapping_func(char *line, int line_num, void *user_data)
{
  const int *p_last_line_num = (const int *) (user_data);
  if (!TEST_CHECK(strcmp(line, lines[line_num - 1]) == 0))
  {
    TEST_MSG("Expected: %s", lines[line_num - 1]);
    TEST_MSG("Actual: %s", line);
  }
  return (line_num < *p_last_line_num);
}

#define BOOLIFY(x) ((x) ? "true" : "false")

static void test_file_map_lines_breaking_after(int last_line, bool expected)
{
  bool res;
  FILE *fp = SET_UP();
  if (fp == NULL)
    return;
  res = mutt_file_map_lines(mapping_func, &last_line, fp, 0);
  if (!TEST_CHECK(res == expected))
  {
    TEST_MSG("Expected: %s", BOOLIFY(expected));
    TEST_MSG("Actual: %s", BOOLIFY(res));
  }
  TEAR_DOWN(fp);
}

void test_file_map_lines(void)
{
  test_file_map_lines_breaking_after(NUM_TEST_LINES + 1, true);
  test_file_map_lines_breaking_after(0, false);
  test_file_map_lines_breaking_after(1, false);
  test_file_map_lines_breaking_after(NUM_TEST_LINES, false);
}
